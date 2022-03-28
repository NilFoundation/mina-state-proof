// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

import '../cryptography/types.sol';
import '../cryptography/transcript.sol';
import '../commitments/lpc_verifier.sol';
import './permutation_argument.sol';
import '../components/unified_addition.sol';
import '../basic_marshalling.sol';
import '../cryptography/field.sol';

library redshift_verifier {
    /**
     * Proof structure: https://github.com/NilFoundation/crypto3-zk-marshalling/blob/master/include/nil/crypto3/marshalling/zk/types/redshift/proof.hpp
     */

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

    uint256 constant f_parts = 4;

    function parse_proof_map_be(
        bytes memory blob,
        uint256 offset
    )
    internal view returns(types.redshift_proof_map memory proof_map, uint256 proof_size) {
        // skip v_perm_commitment
        proof_map.witness_commitments_offset = basic_marshalling.skip_octet_vector_32_be(blob, offset);
        // skip witness_commitments
        proof_map.T_commitments_offset = basic_marshalling.skip_vector_of_octet_vectors_32_be(blob, proof_map.witness_commitments_offset);
        // skip T_commitments
        proof_map.eval_proof_offset = basic_marshalling.skip_vector_of_octet_vectors_32_be(blob, proof_map.T_commitments_offset);
        // skip challenge
        proof_map.eval_proof_witness_offset = basic_marshalling.skip_uint256_be(blob, proof_map.eval_proof_offset);
        // skip witness
        proof_map.eval_proof_permutation_offset = lpc_verifier.skip_vector_of_proofs_be(blob, proof_map.eval_proof_witness_offset);
        // skip permutation
        proof_map.eval_proof_quotient_offset = lpc_verifier.skip_vector_of_proofs_be(blob, proof_map.eval_proof_permutation_offset);
        // skip quotient
        proof_map.eval_proof_id_permutation_offset = lpc_verifier.skip_vector_of_proofs_be(blob, proof_map.eval_proof_quotient_offset);
        // skip id_permutation
        proof_map.eval_proof_sigma_permutation_offset = lpc_verifier.skip_vector_of_proofs_be(blob, proof_map.eval_proof_id_permutation_offset);
        // skip sigma_permutation
        proof_map.eval_proof_public_input_offset = lpc_verifier.skip_vector_of_proofs_be(blob, proof_map.eval_proof_sigma_permutation_offset);
        // skip public_input
        proof_map.eval_proof_constant_offset = lpc_verifier.skip_vector_of_proofs_be(blob, proof_map.eval_proof_public_input_offset);
        // skip constant
        proof_map.eval_proof_selector_offset = lpc_verifier.skip_vector_of_proofs_be(blob, proof_map.eval_proof_constant_offset);
        // skip selector
        proof_map.eval_proof_special_selectors_offset = lpc_verifier.skip_vector_of_proofs_be(blob, proof_map.eval_proof_selector_offset);
        // skip special_selectors
        proof_size = lpc_verifier.skip_vector_of_proofs_be(blob, proof_map.eval_proof_special_selectors_offset) - offset;
    }


    function parse_verify_proof_be(
        bytes memory blob,
        uint256 offset,
        types.transcript_data memory tr_state,
        types.redshift_proof_map memory proof_map,
        types.lpc_params_type memory params,
        types.redshift_common_data memory common_data
    ) internal view returns(bool result) {
        types.redshift_local_variables memory local_vars;
        // 3. append witness commitments to transcript
        (local_vars.len, local_vars.offset) =
            basic_marshalling.get_skip_length(blob, proof_map.witness_commitments_offset);
        for (uint256 i = 0; i < local_vars.len; i++) {
            transcript.update_transcript_b32_by_offset(tr_state, blob, local_vars.offset + basic_marshalling.LENGTH_OCTETS);
            local_vars.offset = basic_marshalling.skip_octet_vector_32_be(blob, local_vars.offset);
        }

        // 4. prepare evaluaitons of the polynomials that are copy-constrained
        local_vars.len = basic_marshalling.get_length(blob, proof_map.eval_proof_id_permutation_offset);
        types.permutation_argument_eval_params memory permutation_argument_params;
        permutation_argument_params.column_polynomials_values = new uint256[](local_vars.len);
        uint256 witness_columns_amount = basic_marshalling.get_length(blob, proof_map.eval_proof_witness_offset);
        for (uint256 i = 0; i < local_vars.len; i++) {
            for (uint256 j = 0; j < common_data.columns_rotations[i].length; j++) {
                if (common_data.columns_rotations[i][j] == 0) {
                    local_vars.zero_index = j;
                }
            }
            if (i < witness_columns_amount) {
                // require(i != 0, uint2str(lpc_verifier.skip_n_proofs_in_vector_be(
                //         blob,
                //         proof_map.eval_proof_witness_offset,
                //         i
                //     )));
                permutation_argument_params.column_polynomials_values[i] = lpc_verifier.get_z_i_from_proof_be(
                    blob,
                    lpc_verifier.skip_n_proofs_in_vector_be(
                        blob,
                        proof_map.eval_proof_witness_offset,
                        i
                    ),
                    local_vars.zero_index
                );
            }
            else if (
                i < 
                witness_columns_amount +
                    basic_marshalling.get_length(blob, proof_map.eval_proof_public_input_offset)
            ) {
                permutation_argument_params.column_polynomials_values[i] = lpc_verifier.get_z_i_from_proof_be(
                    blob,
                    lpc_verifier.skip_n_proofs_in_vector_be(
                        blob,
                        proof_map.eval_proof_public_input_offset,
                        i - witness_columns_amount
                    ),
                    local_vars.zero_index
                );
            }
            else {
                local_vars.tmp1 = i - witness_columns_amount -
                    basic_marshalling.get_length(blob, proof_map.eval_proof_public_input_offset);
                permutation_argument_params.column_polynomials_values[i] = lpc_verifier.get_z_i_from_proof_be(
                    blob,
                    lpc_verifier.skip_n_proofs_in_vector_be(
                        blob,
                        proof_map.eval_proof_constant_offset,
                        local_vars.tmp1
                    ),
                    local_vars.zero_index
                );
            }
        }

        // 5. permutation argument
        permutation_argument_params.modulus = params.modulus;
        permutation_argument_params.challenge =
            basic_marshalling.get_uint256_be(blob, proof_map.eval_proof_offset);
        permutation_argument_params.id_permutation_ptrs =
            new uint256[](basic_marshalling.get_length(blob, proof_map.eval_proof_id_permutation_offset));
        local_vars.offset = proof_map.eval_proof_id_permutation_offset + basic_marshalling.LENGTH_OCTETS;
        for (uint256 i = 0; i < permutation_argument_params.id_permutation_ptrs.length; i++) {
            permutation_argument_params.id_permutation_ptrs[i] =
                lpc_verifier.get_z_0_ptr_from_proof_be(blob, local_vars.offset);
            local_vars.offset = lpc_verifier.skip_proof_be(blob, local_vars.offset);
        }
        permutation_argument_params.sigma_permutation_ptrs =
            new uint256[](basic_marshalling.get_length(blob, proof_map.eval_proof_sigma_permutation_offset));
        local_vars.offset = proof_map.eval_proof_sigma_permutation_offset + basic_marshalling.LENGTH_OCTETS;
        for (uint256 i = 0; i < permutation_argument_params.sigma_permutation_ptrs.length; i++) {
            permutation_argument_params.sigma_permutation_ptrs[i] =
                lpc_verifier.get_z_0_ptr_from_proof_be(blob, local_vars.offset);
            local_vars.offset = lpc_verifier.skip_proof_be(blob, local_vars.offset);
        }
        permutation_argument_params.perm_polynomial_value =
            lpc_verifier.get_z_i_from_proof_be(
                blob,
                proof_map.eval_proof_permutation_offset + basic_marshalling.LENGTH_OCTETS,
                0
            );
        permutation_argument_params.perm_polynomial_shifted_value =
            lpc_verifier.get_z_i_from_proof_be(
                blob,
                proof_map.eval_proof_permutation_offset + basic_marshalling.LENGTH_OCTETS,
                1
            );
        permutation_argument_params.beta = transcript.get_field_challenge(tr_state, params.modulus);
        permutation_argument_params.gamma = transcript.get_field_challenge(tr_state, params.modulus);
        transcript.update_transcript_b32_by_offset(tr_state, blob, basic_marshalling.LENGTH_OCTETS);
        permutation_argument_params.q_last_eval =
            lpc_verifier.get_z_i_from_proof_be(
                blob,
                proof_map.eval_proof_special_selectors_offset + basic_marshalling.LENGTH_OCTETS,
                0
            );
        permutation_argument_params.q_blind_eval =
            lpc_verifier.get_z_i_from_proof_be(
                blob,
                lpc_verifier.skip_proof_be(
                    blob,
                    proof_map.eval_proof_special_selectors_offset + basic_marshalling.LENGTH_OCTETS
                ),
                0
            );
        uint256[] memory permutation_argument =
            permutation_argument.verify_eval_be(permutation_argument_params);
        // uint256 _x = permutation_argument_params.sigma_permutation_ptrs[11];
        // assembly {
        //     _x := mload(_x)
        // }
        // require(false, uint2str(permutation_argument[2]));

        // // 7. gate argument
        // // TODO: generalize for different components
        // // TODO: generalize method to get assignments length
        // // TODO: add public_input_columns and constant_columns to assignments
        // // TODO: make correct length of assignments_ptrs for general case
        // uint256[] memory assignments_ptrs =
        //     new uint256[](unified_addition_component.WITNESS_ASSIGNMENTS_N);
        // uint256 _i = 0;
        // for (uint256 i = 0; i < unified_addition_component.WITNESS_ASSIGNMENTS_N; i++) {
        //     // TODO: remove for general case
        //     require(common_data.columns_rotations[i].rotations.length == 1);
        //     for (uint256 j = 0; j < common_data.columns_rotations[i].rotations.length; j++) {
        //         assignments_ptrs[_i] =
        //             lpc_verifier.get_z_i_from_proof_be(
        //                 blob,
        //                 lpc_verifier.skip_n_proofs_in_vector_be(
        //                     blob,
        //                     proof_map.eval_proof_witness_offset,
        //                     i
        //                 ),
        //                 j
        //             );
        //         _i++;
        //     }
        // }
        // types.gate_eval_params memory gate_params;
        // gate_params.modulus = params.modulus;
        // gate_params.theta_acc = 1;
        // gate_params.theta = transcript.get_field_challenge(tr_state, params.modulus);
        // gate_params.selector_evaluation =
        //     lpc_verifier.get_z_i_from_proof_be(blob, proof_map.eval_proof_selector_offset, 0);
        // uint256 gate_argument =
        //     unified_addition_component.evaluate_gate_be(assignments_ptrs, gate_params);

        // // 8. alphas computations
        // uint256[] memory alphas = new uint256[](f_parts);
        // transcript.get_field_challenges(tr_state, alphas, params.modulus);
        
        // // 9. Evaluation proof check
        // (local_len, local_offset) = basic_marshalling.get_skip_length(blob, proof_map.T_commitments_offset);
        // for (uint256 i = 0; i < local_len; i++) {
        //     transcript.update_transcript_b32_by_offset(tr_state, blob, local_offset + basic_marshalling.LENGTH_OCTETS);
        // }
        // uint256 challenge = transcript.get_field_challenge(tr_state, params.modulus);
        // if (challenge != basic_marshalling.get_uint256_be(blob, proof_map.eval_proof_offset)) {
        //     return false;
        // }

        // // witnesses
        // (local_len, local_offset) = basic_marshalling.get_skip_length(blob, proof_map.eval_proof_witness_offset);
        // for (uint256 i = 0; i < local_len; i++) {
        //     uint256[] memory evaluation_points_gates = new uint256[](common_data.columns_rotations[i].rotations.length);
        //     for (uint256 j = 0; j < common_data.columns_rotations[i].rotations.length; j++) {
        //         uint256 e = uint256(common_data.columns_rotations[i].rotations[j] + int256(params.modulus)) % params.modulus;
        //         e = field.expmod_static(common_data.omega, e, params.modulus);
        //         assembly {
        //             e := mulmod(
        //                 e,
        //                 challenge,
        //                 mload(params)
        //             )
        //         }
        //         evaluation_points_gates[j] = e;
        //     }
        //     (bool res,) = lpc_verifier.parse_verify_proof_be(
        //         blob,
        //         local_offset,
        //         evaluation_points_gates,
        //         tr_state,
        //         params
        //     );
        //     if (!res) {
        //         return false;
        //     }
        //     local_offset = lpc_verifier.skip_proof_be(blob, local_offset);
        // }

        // // permutation
        // uint256[] memory evaluation_points_permutation = new uint256[](2);
        // evaluation_points_permutation[0] = challenge;
        // evaluation_points_permutation[1] = (challenge * common_data.omega) % params.modulus;
        // (local_len, local_offset) = basic_marshalling.get_skip_length(blob, proof_map.eval_proof_permutation_offset);
        // for (uint256 i = 0; i < local_len; i++) {
        //     (bool res,) = lpc_verifier.parse_verify_proof_be(
        //         blob,
        //         local_offset,
        //         evaluation_points_permutation,
        //         tr_state,
        //         params
        //     );
        //     if (!res) {
        //         return false;
        //     }
        //     local_offset = lpc_verifier.skip_proof_be(blob, local_offset);
        // }

        // // quotient
        // uint256[] memory evaluation_points_quotient = new uint256[](1);
        // evaluation_points_permutation[0] = challenge;
        // (local_len, local_offset) = basic_marshalling.get_skip_length(blob, proof_map.eval_proof_quotient_offset);
        // for (uint256 i = 0; i < local_len; i++) {
        //     (bool res,) = lpc_verifier.parse_verify_proof_be(
        //         blob,
        //         local_offset,
        //         evaluation_points_quotient,
        //         tr_state,
        //         params
        //     );
        //     if (!res) {
        //         return false;
        //     }
        //     local_offset = lpc_verifier.skip_proof_be(blob, local_offset);
        // }

        // // public data
        // (local_len, local_offset) = basic_marshalling.get_skip_length(blob, proof_map.eval_proof_id_permutation_offset);
        // for (uint256 i = 0; i < local_len; i++) {
        //     (bool res,) = lpc_verifier.parse_verify_proof_be(
        //         blob,
        //         local_offset,
        //         evaluation_points_quotient,
        //         tr_state,
        //         params
        //     );
        //     if (!res) {
        //         return false;
        //     }
        //     local_offset = lpc_verifier.skip_proof_be(blob, local_offset);
        // }

        // // sigma
        // (local_len, local_offset) = basic_marshalling.get_skip_length(blob, proof_map.eval_proof_sigma_permutation_offset);
        // for (uint256 i = 0; i < local_len; i++) {
        //     (bool res,) = lpc_verifier.parse_verify_proof_be(
        //         blob,
        //         local_offset,
        //         evaluation_points_quotient,
        //         tr_state,
        //         params
        //     );
        //     if (!res) {
        //         return false;
        //     }
        //     local_offset = lpc_verifier.skip_proof_be(blob, local_offset);
        // }

        // // public_input
        // (local_len, local_offset) = basic_marshalling.get_skip_length(blob, proof_map.eval_proof_public_input_offset);
        // for (uint256 i = 0; i < local_len; i++) {
        //     (bool res,) = lpc_verifier.parse_verify_proof_be(
        //         blob,
        //         local_offset,
        //         evaluation_points_quotient,
        //         tr_state,
        //         params
        //     );
        //     if (!res) {
        //         return false;
        //     }
        //     local_offset = lpc_verifier.skip_proof_be(blob, local_offset);
        // }

        // // constant
        // (local_len, local_offset) = basic_marshalling.get_skip_length(blob, proof_map.eval_proof_constant_offset);
        // for (uint256 i = 0; i < local_len; i++) {
        //     (bool res,) = lpc_verifier.parse_verify_proof_be(
        //         blob,
        //         local_offset,
        //         evaluation_points_quotient,
        //         tr_state,
        //         params
        //     );
        //     if (!res) {
        //         return false;
        //     }
        //     local_offset = lpc_verifier.skip_proof_be(blob, local_offset);
        // }

        // // selector
        // (local_len, local_offset) = basic_marshalling.get_skip_length(blob, proof_map.eval_proof_selector_offset);
        // for (uint256 i = 0; i < local_len; i++) {
        //     (bool res,) = lpc_verifier.parse_verify_proof_be(
        //         blob,
        //         local_offset,
        //         evaluation_points_quotient,
        //         tr_state,
        //         params
        //     );
        //     if (!res) {
        //         return false;
        //     }
        //     local_offset = lpc_verifier.skip_proof_be(blob, local_offset);
        // }

        // // special_selectors
        // (local_len, local_offset) = basic_marshalling.get_skip_length(blob, proof_map.eval_proof_special_selectors_offset);
        // for (uint256 i = 0; i < local_len; i++) {
        //     (bool res,) = lpc_verifier.parse_verify_proof_be(
        //         blob,
        //         local_offset,
        //         evaluation_points_quotient,
        //         tr_state,
        //         params
        //     );
        //     if (!res) {
        //         return false;
        //     }
        //     local_offset = lpc_verifier.skip_proof_be(blob, local_offset);
        // }

        // // 10. final check
        // uint256[] memory F = new uint256[](f_parts);
        // F[0] = permutation_argument[0];
        // F[1] = permutation_argument[1];
        // F[2] = permutation_argument[2];
        // F[3] = gate_argument;

        // uint256 F_consolidated = 0;
        // for (uint256 i = 0; i < f_parts; i++) {
        //     assembly {
        //         F_consolidated := addmod(
        //             F_consolidated,
        //             mulmod(
        //                 mload(add(add(alphas, 0x20), mul(0x20, i))),
        //                 mload(add(add(F, 0x20), mul(0x20, i))),
        //                 mload(params)
        //             ),
        //             mload(params)
        //         )
        //     }
        // }

        // uint256 T_consolidated = 0;
        // (local_len, local_offset) = basic_marshalling.get_skip_length(blob, proof_map.eval_proof_quotient_offset);
        // for (uint256 i = 0; i < local_len; i++) {
        //     uint256 z_0 = lpc_verifier.get_z_i_from_proof_be(blob, local_offset, 0);
        //     z_0 = (z_0 * field.expmod_static(challenge, (params.fri_params.max_degree + 1) * i, params.modulus)) % params.modulus;
        //     T_consolidated = (T_consolidated + z_0) % params.modulus;
        //     local_offset = lpc_verifier.skip_proof_be(blob, local_offset);
        // }

        // uint256 Z_at_challenge = field.expmod_static(challenge, common_data.rows_amount, params.modulus);

        // if (F_consolidated != (Z_at_challenge * T_consolidated) % params.modulus) {
        //     return false;
        // }

        return true;
    }

}
