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

import './merkle_verifier_adapted.sol';
import './cryptography/transcript_updated.sol';
import './cryptography/types.sol';
//import './field_math.sol';
//import './cryptography/polynomial_adapted.sol';

library fri_verifier_adapted {

    uint256 constant m = 2;

    struct params_type {
        uint256 modulus;
        uint256 r;
        uint256 max_degree;

        uint256[] D_omegas;
        uint256[] q;
    }

    struct round_proof_type {
        uint256 colinear_value;
        bytes32 T_root;
        uint256[] y;
        merkle_verifier_adapted.merkle_proof colinear_path;
        merkle_verifier_adapted.merkle_proof[] p;
    }

    struct proof_type {
        uint256[] final_polynomial;
        round_proof_type[] round_proofs;
    }

    function parse_round_proof_be(bytes memory blob, uint256 offset)
    internal pure returns (round_proof_type memory proof, uint256 proof_size) {
        require(offset < blob.length);
        uint256 len = blob.length - offset;

        uint256 local_offset = offset;
        uint256 value_len = 0;
        uint256 value = 0;
        bytes32 hash_value;
        proof_size = 0;

        // colinear_value
        proof_size += 32;
        require(proof_size <= len);
        assembly {
            value := mload(add(add(blob, 0x20), local_offset))
        }
        proof.colinear_value = value;
        local_offset += 32; // colinear_value

        // T_root
        // TODO: add T_root length check
        proof_size += 8;
        require(proof_size <= len);
        local_offset += 8; // T_root length
        proof_size += 32;
        require(proof_size <= len);
        assembly {
            hash_value := mload(add(add(blob, 0x20), local_offset))
        }
        proof.T_root = hash_value;
        local_offset += 32; // T_root

        // y
        proof_size += 8;
        require(proof_size <= len);
        value_len = 0;
        for (uint256 i = 0; i < 8; i++) {
            value_len <<= 8;
            value_len |= uint256(uint8(blob[local_offset]));
            local_offset += 1;
        }
        proof_size += 32 * value_len;
        require(proof_size <= len);
        uint256[] memory y = new uint256[](value_len);
        for (uint256 i = 0; i < value_len; i++) {
            assembly {
                value := mload(add(add(blob, 0x20), local_offset))
            }
            y[i] = value;
            local_offset += 32; // y[i]
        }
        proof.y = y;

        // colinear_path
        (proof.colinear_path, value_len) = merkle_verifier_adapted.parse_merkle_proof_be(blob, local_offset);
        proof_size += value_len;
        local_offset += value_len;

        // p
        proof_size += 8;
        require(proof_size <= len);
        value_len = 0;
        for (uint256 i = 0; i < 8; i++) {
            value_len <<= 8;
            value_len |= uint256(uint8(blob[local_offset]));
            local_offset += 1;
        }
        merkle_verifier_adapted.merkle_proof[] memory p = new merkle_verifier_adapted.merkle_proof[](value_len);
        for (uint256 i = 0; i < value_len; i++) {
            (p[i], value) = merkle_verifier_adapted.parse_merkle_proof_be(blob, local_offset);
            proof_size += value;
            local_offset += value;
        }
        proof.p = p;
    }

    function parse_proof_be(bytes memory blob, uint256 offset)
    internal pure returns (proof_type memory proof, uint256 proof_size) {
        require(offset < blob.length);
        uint256 len = blob.length - offset;

        uint256 local_offset = offset;
        uint256 value_len = 0;
        uint256 value = 0;
        proof_size = 0;

        // final_polynomial
        proof_size += 8;
        require(proof_size <= len);
        value_len = 0;
        for (uint256 i = 0; i < 8; i++) {
            value_len <<= 8;
            value_len |= uint256(uint8(blob[local_offset]));
            local_offset += 1;
        }
        proof_size += 32 * value_len;
        require(proof_size <= len);
        uint256[] memory final_polynomial = new uint256[](value_len);
        for (uint256 i = 0; i < value_len; i++) {
            assembly {
                value := mload(add(add(blob, 0x20), local_offset))
            }
            final_polynomial[i] = value;
            local_offset += 32; // final_polynomial[i]
        }
        proof.final_polynomial = final_polynomial;

        // round_proofs
        proof_size += 8;
        require(proof_size <= len);
        value_len = 0;
        for (uint256 i = 0; i < 8; i++) {
            value_len <<= 8;
            value_len |= uint256(uint8(blob[local_offset]));
            local_offset += 1;
        }
        round_proof_type[] memory round_proofs = new round_proof_type[](value_len);
        for (uint256 i = 0; i < value_len; i++) {
            (round_proofs[i], value) = parse_round_proof_be(blob, local_offset);
            proof_size += value;
            local_offset += value;
        }
        proof.round_proofs = round_proofs;
    }

    //
//    function verifyProof(
//        bytes memory proof,
//        transcript_updated.transcript_data memory transcript,
//        fri_params_type memory fri_params,
//        uint256[] memory U,
//        uint256[] memory V
//    ) internal view returns(bool result) {
//        uint256 modulus = fri_params.modulus;
//        uint256 idx = transcript_updated.get_integral_challenge_be(transcript, 8);
//        uint256 x = field_math.pow_small(fri_params.D[0].get_domain_element(1), idx, modulus);
//
//        uint256[2] s;
//        for (uint256 i = 0; i < fri_params.r; i++) {
//            uint256 alpha = transcript_updated.get_field_challenge();
//            uint256 x_next = polynomial_adapted.evaluate(fri_params.q, x, modulus);
//
//            s[0] = x;
//            s[1] = modulus - x;
//
//            for (uint256 j = 0; j < m; j++) {
//                // TODO: get_merkle_proof, get_leaf_data
//                if (!merkle_verifier_adapted.verify_merkle_proof(get_merkle_proof(proof, i, j), get_leaf_data(proof, i, j))) {
//                    return false;
//                }
//            }
//        }
//    }
}
