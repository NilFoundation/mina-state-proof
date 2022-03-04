// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//
pragma solidity >=0.6.0;

import './merkle_verifier.sol';
import './cryptography/transcript.sol';
import './field_math.sol';
import './cryptography/polynomial.sol';

library fri_verifier {

    uint256 constant m = 2;

    struct params_type {
        uint256 modulus;
        uint256 r;
        uint256 max_degree;

        uint256[] D_omegas;
        uint256[] q;

        uint256[] U;
        uint256[] V;
    }

    struct round_proof_type {
        uint256 colinear_value;
        bytes32 T_root;
        uint256[] y;
        merkle_verifier.merkle_proof colinear_path;
        merkle_verifier.merkle_proof[] p;
    }

    struct proof_type {
        uint256[] final_polynomial;
        round_proof_type[] round_proofs;
    }

    struct local_vars_type {
        uint256 x;
        uint256 x_next;
        uint256 alpha;
        uint256[] y;
    }

    function uint2str(uint _i) internal pure returns (string memory _uintAsString) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (_i != 0) {
            k = k-1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }

    function parse_round_proof_be(bytes memory blob, uint256 offset)
    internal pure returns (round_proof_type memory proof, uint256 proof_size) {
        require(offset < blob.length);
        uint256 len = blob.length - offset;
        uint256 value_len;
        proof_size = 0;

        // colinear_value
        assembly {
            proof_size := add(proof_size, 0x20)
        }
        require(proof_size <= len);
        assembly {
            mstore(proof, mload(add(blob, add(0x20, offset))))
            offset := add(offset, 0x20)
        }

        // T_root
        // TODO: add T_root length check
        assembly {
            proof_size := add(proof_size, 8)
        }
        require(proof_size <= len);
        offset += 8; // T_root length
        proof_size += 32;
        require(proof_size <= len);
        assembly {
            mstore(add(proof, 0x20), mload(add(blob, add(0x20, offset))))
            offset := add(offset, 0x20)
        }

        // y
        assembly {
            proof_size := add(proof_size, 8)
        }
        require(proof_size <= len);
        assembly {
            value_len := shr(0xc0, mload(add(add(blob, 0x20), offset)))
            offset := add(offset, 8)
            proof_size := add(proof_size, mul(0x20, value_len))
        }
        require(proof_size <= len);
        proof.y = new uint256[](value_len);
        assembly {
            let y_ptr := add(mload(add(proof, 0x40)), 0x20)
            for { let i := 0 }
            lt(i, mul(0x20, value_len))
            { i := add(i, 0x20) } {
                mstore(add(y_ptr, i), mload(add(add(blob, 0x20), offset)))
                offset := add(offset, 0x20)
            }
        }

        // colinear_path
        (proof.colinear_path, value_len) = merkle_verifier.parse_merkle_proof_be(blob, offset);
        assembly {
            proof_size := add(proof_size, value_len)
            offset := add(offset, value_len)
        }

        // p
        assembly {
            proof_size := add(proof_size, 8)
        }
        require(proof_size <= len);
        assembly {
            value_len := shr(0xc0, mload(add(add(blob, 0x20), offset)))
            offset := add(offset, 8)
        }
        proof.p = new merkle_verifier.merkle_proof[](value_len);
        merkle_verifier.merkle_proof memory p;
        for (uint256 i = 0; i < value_len; i++) {
            (p, len) = merkle_verifier.parse_merkle_proof_be(blob, offset);
            assembly {
                mstore(add(mload(add(proof, 0x80)), add(0x20, mul(0x20, i))), p)
                proof_size := add(proof_size, len)
                offset := add(offset, len)
            }
        }
    }

    function parse_proof_be(bytes memory blob, uint256 offset)
    internal pure returns (proof_type memory proof, uint256 proof_size) {
        require(offset < blob.length);
        uint256 len = blob.length - offset;
        uint256 value_len;
        proof_size = 0;

        // final_polynomial
        assembly {
            proof_size := add(proof_size, 8)
        }
        require(proof_size <= len);
        assembly {
            value_len := shr(0xc0, mload(add(add(blob, 0x20), offset)))
            offset := add(offset, 8)
            proof_size := add(proof_size, mul(0x20, value_len))
        }
        require(proof_size <= len);
        proof.final_polynomial = new uint256[](value_len);
        assembly {
            let final_polynomial_ptr := add(mload(proof), 0x20)
            for { let i := 0 }
            lt(i, mul(0x20, value_len))
            { i := add(i, 0x20) } {
                mstore(add(final_polynomial_ptr, i), mload(add(add(blob, 0x20), offset)))
                offset := add(offset, 0x20)
            }
        }

        // round_proofs
        assembly {
            proof_size := add(proof_size, 8)
        }
        require(proof_size <= len);
        assembly {
            value_len := shr(0xc0, mload(add(add(blob, 0x20), offset)))
            offset := add(offset, 8)
        }
        proof.round_proofs = new round_proof_type[](value_len);
        round_proof_type memory p;
        for (uint256 i = 0; i < value_len; i++) {
            (p, len) = parse_round_proof_be(blob, offset);
            assembly {
                mstore(add(mload(add(proof, 0x20)), add(0x20, mul(0x20, i))), p)
                proof_size := add(proof_size, len)
                offset := add(offset, len)
            }
        }
    }

    function verify_round_proofs(
        proof_type memory proof,
        uint256 i
    ) internal view returns(bool) {
        for (uint256 j = 0; j < m; j++) {
            if (!merkle_verifier.verify_merkle_proof(
                    proof.round_proofs[i].p[j],
                    bytes32(proof.round_proofs[i].y[j])
                )
            ) {
                return false;
            }
        }
        return true;
    }

    function eval_y(
        uint256 i,
        uint256 j,
        uint256 x,
        proof_type memory proof,
        params_type memory fri_params
    ) internal view returns(uint256 result) {
        uint256 U_evaluated_neg;
        uint256 V_evaluated_inv;
        if (i == 0) {
            if (j == 0) {
                U_evaluated_neg = fri_params.modulus -
                    polynomial.evaluate(
                        fri_params.U,
                        x,
                        fri_params.modulus
                    );
                V_evaluated_inv = field_math.inverse_static(
                    polynomial.evaluate(
                        fri_params.V,
                        x,
                        fri_params.modulus
                    ),
                    fri_params.modulus
                );
            } else if (j == 1) {
                U_evaluated_neg = fri_params.modulus -
                    polynomial.evaluate(
                        fri_params.U,
                        fri_params.modulus - x,
                        fri_params.modulus
                    );
                V_evaluated_inv = field_math.inverse_static(
                    polynomial.evaluate(
                        fri_params.V,
                        fri_params.modulus - x,
                        fri_params.modulus
                    ),
                    fri_params.modulus
                );
            }
            result = proof.round_proofs[i].y[j];
            assembly {
                result := mulmod(addmod(result, U_evaluated_neg, mload(fri_params)), V_evaluated_inv, mload(fri_params))
            }
        }
        else {
            result = proof.round_proofs[i].y[j];
        }
    }

    //
    function verifyProof(
        proof_type memory proof,
        transcript.transcript_data memory tr_state,
        params_type memory fri_params
    ) internal view returns(bool) {
        local_vars_type memory local_vars;
        local_vars.y = new uint256[](2);
        local_vars.x = field_math.expmod_static(
            fri_params.D_omegas[0],
            transcript.get_integral_challenge_be(tr_state, 8),
            fri_params.modulus
        );

        for (uint256 i = 0; i < fri_params.r; i++) {
            local_vars.alpha = transcript.get_field_challenge(tr_state, fri_params.modulus);
            local_vars.x_next = polynomial.evaluate(fri_params.q, local_vars.x, fri_params.modulus);

            if (!verify_round_proofs(proof, i)) {
                return false;
            }

            for (uint256 j = 0; j < m; j++) {
                local_vars.y[j] = eval_y(i, j, local_vars.x, proof, fri_params);
            }

            if (polynomial.interpolate_evaluate_by_2_points_neg_x(
                    local_vars.x,
                    field_math.inverse_static((2 * local_vars.x) % fri_params.modulus, fri_params.modulus),
                    local_vars.y[0],
                    local_vars.y[1],
                    local_vars.alpha,
                    fri_params.modulus
                ) != proof.round_proofs[i].colinear_value
            ) {
                return false;
            }

            if (i < fri_params.r - 1) {
                transcript.update_transcript_b32(tr_state, proof.round_proofs[i + 1].T_root);
                if (!merkle_verifier.verify_merkle_proof(
                        proof.round_proofs[i].colinear_path,
                        bytes32(proof.round_proofs[i].colinear_value)
                    )
                ) {
                    return false;
                }
            }

            local_vars.x = local_vars.x_next;
        }

        if (proof.final_polynomial.length - 1 >
            uint256(2) ** (field_math.log2(fri_params.max_degree + 1) - fri_params.r) - 1
        ) {
            return false;
        }

        if (polynomial.evaluate(proof.final_polynomial, local_vars.x, fri_params.modulus) !=
            proof.round_proofs[fri_params.r - 1].colinear_value
        ) {
            return false;
        }

        return true;
    }
}
