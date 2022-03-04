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

import './fri_verifier_adapted.sol';
import './cryptography/polynomial_adapted.sol';

library lpc_verifier {

    uint256 constant m = 2;

    struct params_type {
        uint256 modulus;
        uint256 lambda;
        uint256 r;
        uint256 m;
        uint256 k;
        fri_verifier_adapted.params_type fri_params;
    }

    struct proof_type {
        bytes32 T_root;
        uint256[] z;
        fri_verifier_adapted.proof_type[] fri_proof;
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

    function parse_proof_be(bytes memory blob, uint256 offset)
    internal pure returns (proof_type memory proof, uint256 proof_size) {
        require(offset < blob.length);
        uint256 len = blob.length - offset;
        uint256 value_len;
        proof_size = 0;

        // T_root
        // TODO: add T_root length check
        assembly {
            proof_size := add(proof_size, 8)
        }
        require(proof_size <= len);
        assembly {
            offset := add(offset, 8) // T_root length
            proof_size := add(proof_size, 0x20)
        }
        require(proof_size <= len);
        assembly {
            mstore(proof, mload(add(blob, add(0x20, offset))))
            offset := add(offset, 0x20)
        }

        // z
        assembly {
            proof_size := add(proof_size, 8)
        }
        require(proof_size <= len);
        assembly {
            value_len := shr(0xc0, mload(add(blob, add(0x20, offset))))
            offset := add(offset, 8)
            proof_size := add(proof_size, mul(0x20, value_len))
        }
        require(proof_size <= len);
        proof.z = new uint256[](value_len);
        assembly {
            let z_ptr := add(mload(add(proof, 0x20)), 0x20)
            for { let i := 0 }
            lt(i, mul(0x20, value_len))
            { i := add(i, 0x20) } {
                mstore(add(z_ptr, i), mload(add(blob, add(0x20, offset))))
                offset := add(offset, 0x20)
            }
        }

        // fri_proof
        assembly {
            proof_size := add(proof_size, 8)
        }
        require(proof_size <= len);
        assembly {
            value_len := shr(0xc0, mload(add(blob, add(0x20, offset))))
            offset := add(offset, 8)
        }
        proof.fri_proof = new fri_verifier_adapted.proof_type[](value_len);
        fri_verifier_adapted.proof_type memory p;
        for (uint256 i = 0; i < value_len; i++) {
            (p, len) = fri_verifier_adapted.parse_proof_be(blob, offset);
            assembly {
                mstore(add(mload(add(proof, 0x40)), add(0x20, mul(0x20, i))), p)
                proof_size := add(proof_size, len)
                offset := add(offset, len)
            }
        }
    }

    //
    function verifyProof(
        uint256[] memory evaluation_points,
        proof_type memory proof,
        transcript_updated.transcript_data memory transcript,
        params_type memory params
    ) internal view returns(bool) {
        require(evaluation_points.length == proof.z.length, "Number of evaluation points is not correct");
        params.fri_params.U = polynomial_adapted.interpolate(evaluation_points, proof.z, params.modulus);
        params.fri_params.V = new uint256[](1);
        params.fri_params.V[0] = 1;
        uint256[] memory a_poly = new uint256[](2);
        a_poly[1] = 1;
        for (uint256 j = 0; j < evaluation_points.length; j++) {
            a_poly[0] = params.modulus - evaluation_points[j];
            params.fri_params.V = polynomial_adapted.mul_poly(params.fri_params.V, a_poly, params.modulus);
        }
        for (uint256 round_id = 0; round_id < params.lambda; round_id++) {
            if (!fri_verifier_adapted.verifyProof(proof.fri_proof[round_id], transcript, params.fri_params)) {
                return false;
            }
        }
        return true;
    }
}
