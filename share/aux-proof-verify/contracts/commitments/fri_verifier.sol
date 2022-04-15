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
pragma solidity >=0.8.4;

import "../types.sol";
import "../containers/merkle_verifier.sol";
import "../cryptography/transcript.sol";
import "../algebra/field.sol";
import "../algebra/polynomial.sol";
import "../basic_marshalling.sol";

library fri_verifier {
    struct local_vars_type {
        uint256 len;
        uint256 colinear_value;
        bytes32 T_root;
        uint256 final_poly_len;
        uint256 x;
        uint256 x_next;
        uint256 alpha;
        uint256[] y;
    }

    struct round_proof_verification_local_vars {
        bytes32 y;
        uint256 len;
        uint256 mp_size;
        bool result_j;
    }

    uint256 constant m = 2;
    uint256 constant ROUND_PROOF_Y_OFFSET = 0x48;

    function parse_round_proof_be(bytes memory blob, uint256 offset)
        internal
        pure
        returns (types.fri_round_proof_type memory proof, uint256 proof_size)
    {
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
            for {
                let i := 0
            } lt(i, mul(0x20, value_len)) {
                i := add(i, 0x20)
            } {
                mstore(add(y_ptr, i), mload(add(add(blob, 0x20), offset)))
                offset := add(offset, 0x20)
            }
        }

        // colinear_path
        (proof.colinear_path, value_len) = merkle_verifier
            .parse_merkle_proof_be(blob, offset);
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
        proof.p = new types.merkle_proof[](value_len);
        types.merkle_proof memory p;
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
        internal
        pure
        returns (types.fri_proof_type memory proof, uint256 proof_size)
    {
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
            for {
                let i := 0
            } lt(i, mul(0x20, value_len)) {
                i := add(i, 0x20)
            } {
                mstore(
                    add(final_polynomial_ptr, i),
                    mload(add(add(blob, 0x20), offset))
                )
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
        proof.round_proofs = new types.fri_round_proof_type[](value_len);
        types.fri_round_proof_type memory p;
        for (uint256 i = 0; i < value_len; i++) {
            (p, len) = parse_round_proof_be(blob, offset);
            assembly {
                mstore(add(mload(add(proof, 0x20)), add(0x20, mul(0x20, i))), p)
                proof_size := add(proof_size, len)
                offset := add(offset, len)
            }
        }
    }

    function skip_round_proof_be(bytes memory blob, uint256 offset)
        internal
        pure
        returns (uint256 result_offset)
    {
        // colinear_value
        result_offset = basic_marshalling.skip_uint256_be(blob, offset);
        // T_root
        result_offset = basic_marshalling.skip_octet_vector_32_be(
            blob,
            result_offset
        );
        // y
        result_offset = basic_marshalling.skip_vector_of_uint256_be(
            blob,
            result_offset
        );
        // colinear_path
        result_offset = merkle_verifier.skip_merkle_proof_be(
            blob,
            result_offset
        );
        // p
        uint256 value_len;
        (value_len, result_offset) = basic_marshalling.get_skip_length(
            blob,
            result_offset
        );
        for (uint256 i = 0; i < value_len; i++) {
            result_offset = merkle_verifier.skip_merkle_proof_be(
                blob,
                result_offset
            );
        }
    }

    function skip_proof_be(bytes memory blob, uint256 offset)
        internal
        pure
        returns (uint256 result_offset)
    {
        // final_polynomial
        result_offset = basic_marshalling.skip_vector_of_uint256_be(
            blob,
            offset
        );
        // round_proofs
        uint256 value_len;
        (value_len, result_offset) = basic_marshalling.get_skip_length(
            blob,
            result_offset
        );
        for (uint256 i = 0; i < value_len; i++) {
            result_offset = skip_round_proof_be(blob, result_offset);
        }
    }

    function skip_round_proof_be_check(bytes memory blob, uint256 offset)
        internal
        pure
        returns (uint256 result_offset)
    {
        // colinear_value
        result_offset = basic_marshalling.skip_uint256_be_check(blob, offset);
        // T_root
        result_offset = basic_marshalling.skip_octet_vector_32_be_check(
            blob,
            result_offset
        );
        // y
        result_offset = basic_marshalling.skip_vector_of_uint256_be_check(
            blob,
            result_offset
        );
        // colinear_path
        result_offset = merkle_verifier.skip_merkle_proof_be_check(
            blob,
            result_offset
        );
        // p
        uint256 value_len;
        (value_len, result_offset) = basic_marshalling.get_skip_length_check(
            blob,
            result_offset
        );
        for (uint256 i = 0; i < value_len; i++) {
            result_offset = merkle_verifier.skip_merkle_proof_be_check(
                blob,
                result_offset
            );
        }
    }

    function skip_proof_be_check(bytes memory blob, uint256 offset)
        internal
        pure
        returns (uint256 result_offset)
    {
        // final_polynomial
        result_offset = basic_marshalling.skip_vector_of_uint256_be_check(
            blob,
            offset
        );
        // round_proofs
        uint256 value_len;
        (value_len, result_offset) = basic_marshalling.get_skip_length_check(
            blob,
            result_offset
        );
        for (uint256 i = 0; i < value_len; i++) {
            result_offset = skip_round_proof_be_check(blob, result_offset);
        }
    }

    function verify_round_proofs(types.fri_proof_type memory proof, uint256 i)
        internal
        pure
        returns (bool)
    {
        for (uint256 j = 0; j < m; j++) {
            if (
                !merkle_verifier.verify_merkle_proof(
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
        types.fri_proof_type memory proof,
        types.fri_params_type memory fri_params
    ) internal view returns (uint256 result) {
        uint256 U_evaluated_neg;
        uint256 V_evaluated_inv;
        if (i == 0) {
            if (j == 0) {
                U_evaluated_neg =
                    fri_params.modulus -
                    polynomial.evaluate(fri_params.U, x, fri_params.modulus);
                V_evaluated_inv = field.inverse_static(
                    polynomial.evaluate(fri_params.V, x, fri_params.modulus),
                    fri_params.modulus
                );
            } else if (j == 1) {
                U_evaluated_neg =
                    fri_params.modulus -
                    polynomial.evaluate(
                        fri_params.U,
                        fri_params.modulus - x,
                        fri_params.modulus
                    );
                V_evaluated_inv = field.inverse_static(
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
                result := mulmod(
                    addmod(result, U_evaluated_neg, mload(fri_params)),
                    V_evaluated_inv,
                    mload(fri_params)
                )
            }
        } else {
            result = proof.round_proofs[i].y[j];
        }
    }

    function eval_y_from_blob(
        bytes memory blob,
        uint256 offset,
        uint256 i,
        uint256 j,
        uint256 x,
        types.fri_params_type memory fri_params
    ) internal view returns (uint256 result) {
        assembly {
            result := mload(
                add(
                    add(blob, 0x20),
                    add(add(add(offset, ROUND_PROOF_Y_OFFSET), 8), mul(0x20, j))
                )
            )
        }
        if (i == 0) {
            uint256 U_evaluated_neg;
            uint256 V_evaluated_inv;
            if (j == 0) {
                U_evaluated_neg =
                    fri_params.modulus -
                    polynomial.evaluate(fri_params.U, x, fri_params.modulus);
                V_evaluated_inv = field.inverse_static(
                    polynomial.evaluate(fri_params.V, x, fri_params.modulus),
                    fri_params.modulus
                );
            } else if (j == 1) {
                U_evaluated_neg =
                    fri_params.modulus -
                    polynomial.evaluate(
                        fri_params.U,
                        fri_params.modulus - x,
                        fri_params.modulus
                    );
                V_evaluated_inv = field.inverse_static(
                    polynomial.evaluate(
                        fri_params.V,
                        fri_params.modulus - x,
                        fri_params.modulus
                    ),
                    fri_params.modulus
                );
            }
            assembly {
                result := mulmod(
                    addmod(result, U_evaluated_neg, mload(fri_params)),
                    V_evaluated_inv,
                    mload(fri_params)
                )
            }
        }
    }

    //
    function verifyProof(
        types.fri_proof_type memory proof,
        types.transcript_data memory tr_state,
        types.fri_params_type memory fri_params
    ) internal view returns (bool) {
        local_vars_type memory local_vars;
        local_vars.y = new uint256[](2);
        local_vars.x = field.expmod_static(
            fri_params.D_omegas[0],
            transcript.get_integral_challenge_be(tr_state, 8),
            fri_params.modulus
        );

        for (uint256 i = 0; i < fri_params.r; i++) {
            local_vars.alpha = transcript.get_field_challenge(
                tr_state,
                fri_params.modulus
            );
            local_vars.x_next = polynomial.evaluate(
                fri_params.q,
                local_vars.x,
                fri_params.modulus
            );

            if (!verify_round_proofs(proof, i)) {
                return false;
            }

            for (uint256 j = 0; j < m; j++) {
                local_vars.y[j] = eval_y(i, j, local_vars.x, proof, fri_params);
            }

            if (
                polynomial.interpolate_evaluate_by_2_points_neg_x(
                    local_vars.x,
                    field.inverse_static(
                        (2 * local_vars.x) % fri_params.modulus,
                        fri_params.modulus
                    ),
                    local_vars.y[0],
                    local_vars.y[1],
                    local_vars.alpha,
                    fri_params.modulus
                ) != proof.round_proofs[i].colinear_value
            ) {
                return false;
            }

            if (i < fri_params.r - 1) {
                transcript.update_transcript_b32(
                    tr_state,
                    proof.round_proofs[i + 1].T_root
                );
                if (
                    !merkle_verifier.verify_merkle_proof(
                        proof.round_proofs[i].colinear_path,
                        bytes32(proof.round_proofs[i].colinear_value)
                    )
                ) {
                    return false;
                }
            }

            local_vars.x = local_vars.x_next;
        }

        if (
            proof.final_polynomial.length - 1 >
            uint256(2)**(field.log2(fri_params.max_degree + 1) - fri_params.r) -
                1
        ) {
            return false;
        }

        if (
            polynomial.evaluate(
                proof.final_polynomial,
                local_vars.x,
                fri_params.modulus
            ) != proof.round_proofs[fri_params.r - 1].colinear_value
        ) {
            return false;
        }

        return true;
    }

    function parse_verify_round_proof_be(bytes memory blob, uint256 offset)
        internal
        pure
        returns (bool result, uint256 proof_size)
    {
        require(offset < blob.length);
        round_proof_verification_local_vars memory vars;
        vars.len = blob.length - offset;

        proof_size += (ROUND_PROOF_Y_OFFSET + 8);
        require(proof_size <= vars.len);
        assembly {
            let y_len := shr(
                0xc0,
                mload(add(add(blob, 0x20), add(offset, ROUND_PROOF_Y_OFFSET)))
            )
            // size of y should be equal to m
            if eq(eq(y_len, m), 0) {
                mstore(0, 1)
                revert(0, 0x20)
            }
            proof_size := add(proof_size, mul(0x20, y_len))
        }
        require(proof_size <= vars.len);
        // skip colinear_path
        proof_size += merkle_verifier.get_merkle_proof_size_be(
            blob,
            offset + proof_size
        );
        require(proof_size + 8 <= vars.len);
        assembly {
            let p_len := shr(
                0xc0,
                mload(add(add(blob, 0x20), add(offset, proof_size)))
            )
            // size of p should be equal to m
            if eq(eq(p_len, m), 0) {
                mstore(0, 1)
                revert(0, 0x20)
            }
        }
        proof_size += 8;
        for (uint256 j = 0; j < m; j++) {
            assembly {
                mstore(
                    vars,
                    mload(
                        add(
                            add(blob, 0x20),
                            add(
                                add(offset, add(ROUND_PROOF_Y_OFFSET, 8)),
                                mul(0x20, j)
                            )
                        )
                    )
                )
            }
            (vars.result_j, vars.mp_size) = merkle_verifier
                .parse_verify_merkle_proof_be(
                    blob,
                    offset + proof_size,
                    vars.y
                );
            if (!vars.result_j) {
                return (false, 0);
            }
            proof_size += vars.mp_size;
        }
        result = true;
    }

    function parse_verify_proof_be(
        bytes memory blob,
        uint256 offset,
        types.transcript_data memory tr_state,
        types.fri_params_type memory fri_params
    ) internal view returns (bool result, uint256 proof_size) {
        result = false;
        require(offset < blob.length);

        local_vars_type memory local_vars;
        local_vars.len = blob.length - offset;
        local_vars.y = new uint256[](2);
        local_vars.x = field.expmod_static(
            fri_params.D_omegas[0],
            transcript.get_integral_challenge_be(tr_state, 8),
            fri_params.modulus
        );

        require(8 <= local_vars.len);
        assembly {
            let final_poly_len := shr(0xc0, mload(add(add(blob, 0x20), offset)))
            mstore(add(local_vars, 0x60), final_poly_len)
            proof_size := add(8, mul(0x20, final_poly_len))
            // local_vars.len should be >= proof_size
            if lt(mload(local_vars), add(8, proof_size)) {
                revert(0, 0)
            }
            let round_proofs_len := shr(
                0xc0,
                mload(add(add(blob, 0x20), add(offset, proof_size)))
            )
            proof_size := add(8, proof_size)
            // number of round proofs should be equal to r
            if eq(
                eq(
                    round_proofs_len,
                    // fri_params.r
                    mload(add(fri_params, 0x20))
                ),
                0
            ) {
                revert(0, 0)
            }
        }

        for (uint256 i = 0; i < fri_params.r; i++) {
            local_vars.alpha = transcript.get_field_challenge(
                tr_state,
                fri_params.modulus
            );
            local_vars.x_next = polynomial.evaluate(
                fri_params.q,
                local_vars.x,
                fri_params.modulus
            );

            (
                bool result_i,
                uint256 read_round_proof_size
            ) = parse_verify_round_proof_be(blob, offset + proof_size);
            if (!result_i) {
                return (false, 0);
            }

            for (uint256 j = 0; j < m; j++) {
                local_vars.y[j] = eval_y_from_blob(
                    blob,
                    offset + proof_size,
                    i,
                    j,
                    local_vars.x,
                    fri_params
                );
            }
            // get colinear_value
            assembly {
                mstore(
                    add(local_vars, 0x20),
                    mload(add(add(blob, 0x20), add(offset, proof_size)))
                )
            }
            if (
                polynomial.interpolate_evaluate_by_2_points_neg_x(
                    local_vars.x,
                    field.inverse_static(
                        (2 * local_vars.x) % fri_params.modulus,
                        fri_params.modulus
                    ),
                    local_vars.y[0],
                    local_vars.y[1],
                    local_vars.alpha,
                    fri_params.modulus
                ) != local_vars.colinear_value
            ) {
                return (false, 0);
            }

            if (i < fri_params.r - 1) {
                // get round_proofs[i + 1].T_root
                assembly {
                    mstore(
                        add(local_vars, 0x40),
                        mload(
                            add(
                                add(blob, 0x20),
                                add(
                                    add(
                                        add(offset, proof_size),
                                        read_round_proof_size
                                    ),
                                    0x28
                                )
                            )
                        )
                    )
                }
                transcript.update_transcript_b32(tr_state, local_vars.T_root);
                (result_i, ) = merkle_verifier.parse_verify_merkle_proof_be(
                    blob,
                    offset + proof_size + ROUND_PROOF_Y_OFFSET + 8 + m * 0x20,
                    bytes32(local_vars.colinear_value)
                );
                if (!result_i) {
                    return (false, 0);
                }
            }

            local_vars.x = local_vars.x_next;
            proof_size += read_round_proof_size;
        }

        if (
            local_vars.final_poly_len - 1 >
            uint256(2)**(field.log2(fri_params.max_degree + 1) - fri_params.r) -
                1
        ) {
            return (false, 0);
        }

        if (
            polynomial.evaluate_by_ptr(
                blob,
                offset + 8,
                local_vars.final_poly_len,
                local_vars.x,
                fri_params.modulus
            ) != local_vars.colinear_value
        ) {
            return (false, 0);
        }

        result = true;
    }
}
