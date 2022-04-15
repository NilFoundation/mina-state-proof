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

import "../types.sol";
import "../cryptography/transcript.sol";
import "../commitments/lpc_verifier_calldata.sol";
import "./permutation_argument_calldata.sol";
import "../components/unified_addition_calldata.sol";
import "../basic_marshalling_calldata.sol";
import "../algebra/field.sol";

library redshift_verifier_unified_addition_component_calldata {
    uint256 constant f_parts = 9;

    uint256 constant OMEGA_OFFSET = 0x20;

    uint256 constant ZERO_INDEX_OFFSET = 0x40;
    uint256 constant E_OFFSET = 0xe0;
    uint256 constant ALPHAS_OFFSET = 0xa0;
    uint256 constant CHALLENGE_OFFSET = 0xc0;
    uint256 constant EVALUATION_POINTS_OFFSET = 0x100;
    uint256 constant F_OFFSET = 0x120;
    uint256 constant F_CONSOLIDATED_OFFSET = 0x140;
    uint256 constant T_CONSOLIDATED_OFFSET = 0x160;
    uint256 constant Z_AT_CHALLENGE_OFFSET = 0x180;

    function verify_lpc_commitments(
        bytes calldata blob,
        uint256 offset,
        types.transcript_data memory tr_state,
        types.lpc_params_type memory lpc_params,
        types.redshift_local_variables_calldata memory local_vars
    ) internal view returns (bool) {
        (local_vars.len, local_vars.offset) = basic_marshalling_calldata
            .get_skip_length(blob, offset);
        for (uint256 i = 0; i < local_vars.len; i++) {
            (local_vars.status, ) = lpc_verifier_calldata.parse_verify_proof_be(
                blob,
                local_vars.offset,
                local_vars.evaluation_points,
                tr_state,
                lpc_params
            );
            if (!local_vars.status) {
                return false;
            }
            local_vars.offset = lpc_verifier_calldata.skip_proof_be(
                blob,
                local_vars.offset
            );
        }
        return true;
    }

    function verify_proof_be(
        bytes calldata blob,
        types.transcript_data memory tr_state,
        types.redshift_proof_map_calldata memory proof_map,
        types.lpc_params_type memory lpc_params,
        types.redshift_common_data memory common_data
    ) internal view returns (bool result) {
        types.redshift_local_variables_calldata memory local_vars;
        // 3. append witness commitments to transcript
        (local_vars.len, local_vars.offset) = basic_marshalling_calldata
            .get_skip_length(blob, proof_map.witness_commitments_offset);
        for (uint256 i = 0; i < local_vars.len; i++) {
            transcript.update_transcript_b32_by_offset_calldata(
                tr_state,
                blob,
                local_vars.offset + basic_marshalling_calldata.LENGTH_OCTETS
            );
            local_vars.offset = basic_marshalling_calldata
                .skip_octet_vector_32_be(blob, local_vars.offset);
        }

        // 4. prepare evaluaitons of the polynomials that are copy-constrained
        // 5. permutation argument
        local_vars.permutation_argument = permutation_argument_calldata
            .verify_eval_be(
                blob,
                tr_state,
                proof_map,
                lpc_params,
                common_data,
                local_vars
            );

        // 7. gate argument
        types.gate_argument_local_vars memory gate_params;
        gate_params.modulus = lpc_params.modulus;
        gate_params.theta = transcript.get_field_challenge(
            tr_state,
            lpc_params.modulus
        );
        gate_params.eval_proof_witness_offset = proof_map
            .eval_proof_witness_offset;
        gate_params.eval_proof_selector_offset = proof_map
            .eval_proof_selector_offset;
        local_vars.gate_argument = unified_addition_component_calldata
            .evaluate_gates_be(
                blob,
                gate_params,
                common_data.columns_rotations
            );

        // 8. alphas computations
        local_vars.alphas = new uint256[](f_parts);
        transcript.get_field_challenges(
            tr_state,
            local_vars.alphas,
            lpc_params.modulus
        );

        // 9. Evaluation proof check
        (local_vars.len, local_vars.offset) = basic_marshalling_calldata
            .get_skip_length(blob, proof_map.T_commitments_offset);
        for (uint256 i = 0; i < local_vars.len; i++) {
            transcript.update_transcript_b32_by_offset_calldata(
                tr_state,
                blob,
                local_vars.offset + basic_marshalling_calldata.LENGTH_OCTETS
            );
            local_vars.offset = basic_marshalling_calldata
                .skip_octet_vector_32_be(blob, local_vars.offset);
        }
        local_vars.challenge = transcript.get_field_challenge(
            tr_state,
            lpc_params.modulus
        );
        if (
            local_vars.challenge !=
            basic_marshalling_calldata.get_uint256_be(
                blob,
                proof_map.eval_proof_offset
            )
        ) {
            return false;
        }

        // witnesses
        (local_vars.len, local_vars.offset) = basic_marshalling_calldata
            .get_skip_length(blob, proof_map.eval_proof_witness_offset);
        for (uint256 i = 0; i < local_vars.len; i++) {
            local_vars.evaluation_points = new uint256[](
                common_data.columns_rotations[i].length
            );
            for (
                uint256 j = 0;
                j < common_data.columns_rotations[i].length;
                j++
            ) {
                local_vars.e =
                    uint256(
                        common_data.columns_rotations[i][j] +
                            int256(lpc_params.modulus)
                    ) %
                    lpc_params.modulus;
                local_vars.e = field.expmod_static(
                    common_data.omega,
                    local_vars.e,
                    lpc_params.modulus
                );
                assembly {
                    mstore(
                        // evaluation_points[j]
                        add(
                            add(
                                mload(
                                    add(local_vars, EVALUATION_POINTS_OFFSET)
                                ),
                                0x20
                            ),
                            mul(0x20, j)
                        ),
                        // challenge * omega^rotation_gates[j]
                        mulmod(
                            // challenge
                            mload(add(local_vars, CHALLENGE_OFFSET)),
                            // e = omega^rotation_gates[j]
                            mload(add(local_vars, E_OFFSET)),
                            // modulus
                            mload(lpc_params)
                        )
                    )
                }
            }
            (local_vars.status, ) = lpc_verifier_calldata.parse_verify_proof_be(
                blob,
                local_vars.offset,
                local_vars.evaluation_points,
                tr_state,
                lpc_params
            );
            if (!local_vars.status) {
                return false;
            }
            local_vars.offset = lpc_verifier_calldata.skip_proof_be(
                blob,
                local_vars.offset
            );
        }

        // permutation
        local_vars.evaluation_points = new uint256[](2);
        local_vars.evaluation_points[0] = local_vars.challenge;
        // local_vars.evaluation_points_permutation[1] = (local_vars.challenge * common_data.omega) % lpc_params.modulus;
        assembly {
            mstore(
                // local_vars.evaluation_points[1]
                add(mload(add(local_vars, EVALUATION_POINTS_OFFSET)), 0x40),
                // (local_vars.challenge * common_data.omega) % lpc_params.modulus
                mulmod(
                    // local_vars.challenge
                    mload(add(local_vars, CHALLENGE_OFFSET)),
                    // common_data.omega
                    mload(add(common_data, OMEGA_OFFSET)),
                    // modulus
                    mload(lpc_params)
                )
            )
        }
        if (
            !verify_lpc_commitments(
                blob,
                proof_map.eval_proof_permutation_offset,
                tr_state,
                lpc_params,
                local_vars
            )
        ) {
            return false;
        }

        // quotient
        local_vars.evaluation_points = new uint256[](1);
        local_vars.evaluation_points[0] = local_vars.challenge;
        if (
            !verify_lpc_commitments(
                blob,
                proof_map.eval_proof_quotient_offset,
                tr_state,
                lpc_params,
                local_vars
            )
        ) {
            return false;
        }

        // public data
        if (
            !verify_lpc_commitments(
                blob,
                proof_map.eval_proof_id_permutation_offset,
                tr_state,
                lpc_params,
                local_vars
            )
        ) {
            return false;
        }

        // sigma
        if (
            !verify_lpc_commitments(
                blob,
                proof_map.eval_proof_sigma_permutation_offset,
                tr_state,
                lpc_params,
                local_vars
            )
        ) {
            return false;
        }

        // public_input
        if (
            !verify_lpc_commitments(
                blob,
                proof_map.eval_proof_public_input_offset,
                tr_state,
                lpc_params,
                local_vars
            )
        ) {
            return false;
        }

        // constant
        if (
            !verify_lpc_commitments(
                blob,
                proof_map.eval_proof_constant_offset,
                tr_state,
                lpc_params,
                local_vars
            )
        ) {
            return false;
        }

        // selector
        if (
            !verify_lpc_commitments(
                blob,
                proof_map.eval_proof_selector_offset,
                tr_state,
                lpc_params,
                local_vars
            )
        ) {
            return false;
        }

        // special_selectors
        if (
            !verify_lpc_commitments(
                blob,
                proof_map.eval_proof_special_selectors_offset,
                tr_state,
                lpc_params,
                local_vars
            )
        ) {
            return false;
        }

        // 10. final check
        local_vars.F = new uint256[](f_parts);
        local_vars.F[0] = local_vars.permutation_argument[0];
        local_vars.F[1] = local_vars.permutation_argument[1];
        local_vars.F[2] = local_vars.permutation_argument[2];
        // lookup argument is not used in unified addition component
        for (uint256 i = 3; i < 8; i++) {
            local_vars.F[i] = 0;
        }
        local_vars.F[8] = local_vars.gate_argument;

        local_vars.F_consolidated = 0;
        for (uint256 i = 0; i < f_parts; i++) {
            assembly {
                mstore(
                    // local_vars.F_consolidated
                    add(local_vars, F_CONSOLIDATED_OFFSET),
                    addmod(
                        // F_consolidated
                        mload(add(local_vars, F_CONSOLIDATED_OFFSET)),
                        mulmod(
                            // alphas[i]
                            mload(
                                add(
                                    add(
                                        mload(add(local_vars, ALPHAS_OFFSET)),
                                        0x20
                                    ),
                                    mul(0x20, i)
                                )
                            ),
                            // F[i]
                            mload(
                                add(
                                    add(mload(add(local_vars, F_OFFSET)), 0x20),
                                    mul(0x20, i)
                                )
                            ),
                            // modulus
                            mload(lpc_params)
                        ),
                        // modulus
                        mload(lpc_params)
                    )
                )
            }
        }

        local_vars.T_consolidated = 0;
        (local_vars.len, local_vars.offset) = basic_marshalling_calldata
            .get_skip_length(blob, proof_map.eval_proof_quotient_offset);
        for (uint256 i = 0; i < local_vars.len; i++) {
            local_vars.zero_index = lpc_verifier_calldata.get_z_i_from_proof_be(
                blob,
                local_vars.offset,
                0
            );
            local_vars.e = field.expmod_static(
                local_vars.challenge,
                (lpc_params.fri_params.max_degree + 1) * i,
                lpc_params.modulus
            );
            assembly {
                mstore(
                    // local_vars.zero_index
                    add(local_vars, ZERO_INDEX_OFFSET),
                    // local_vars.zero_index * local_vars.e
                    mulmod(
                        // local_vars.zero_index
                        mload(add(local_vars, ZERO_INDEX_OFFSET)),
                        // local_vars.e
                        mload(add(local_vars, E_OFFSET)),
                        // modulus
                        mload(lpc_params)
                    )
                )
                mstore(
                    // local_vars.T_consolidated
                    add(local_vars, T_CONSOLIDATED_OFFSET),
                    // local_vars.T_consolidated + local_vars.zero_index
                    addmod(
                        // local_vars.T_consolidated
                        mload(add(local_vars, T_CONSOLIDATED_OFFSET)),
                        // local_vars.zero_index
                        mload(add(local_vars, ZERO_INDEX_OFFSET)),
                        // modulus
                        mload(lpc_params)
                    )
                )
            }
            local_vars.offset = lpc_verifier_calldata.skip_proof_be(
                blob,
                local_vars.offset
            );
        }

        local_vars.Z_at_challenge = field.expmod_static(
            local_vars.challenge,
            common_data.rows_amount,
            lpc_params.modulus
        );
        assembly {
            mstore(
                // local_vars.Z_at_challenge
                add(local_vars, Z_AT_CHALLENGE_OFFSET),
                // local_vars.Z_at_challenge - 1
                addmod(
                    // Z_at_challenge
                    mload(add(local_vars, Z_AT_CHALLENGE_OFFSET)),
                    // -1
                    sub(mload(lpc_params), 1),
                    // modulus
                    mload(lpc_params)
                )
            )
            mstore(
                // local_vars.Z_at_challenge
                add(local_vars, Z_AT_CHALLENGE_OFFSET),
                // Z_at_challenge * T_consolidated
                mulmod(
                    // Z_at_challenge
                    mload(add(local_vars, Z_AT_CHALLENGE_OFFSET)),
                    // T_consolidated
                    mload(add(local_vars, T_CONSOLIDATED_OFFSET)),
                    // modulus
                    mload(lpc_params)
                )
            )
        }
        if (local_vars.F_consolidated != local_vars.Z_at_challenge) {
            return false;
        }

        return true;
    }
}
