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
import "../basic_marshalling_calldata.sol";
import "../cryptography/transcript.sol";
import "../commitments/lpc_verifier_calldata.sol";

library permutation_argument_calldata {
    uint256 constant ARGUMENT_SIZE = 3;

    uint256 constant CHALLENGE_OFFSET = 0xc0;
    uint256 constant BETA_OFFSET = 0x1a0;
    uint256 constant GAMMA_OFFSET = 0x1c0;
    uint256 constant G_OFFSET = 0x1e0;
    uint256 constant H_OFFSET = 0x200;
    uint256 constant PERM_POLYNOMIAL_VALUE_OFFSET = 0x220;
    uint256 constant PERM_POLYNOMIAL_SHIFTED_VALUE_OFFSET = 0x240;
    uint256 constant Q_BLIND_EVAL_OFFSET = 0x260;
    uint256 constant Q_LAST_EVAL_OFFSET = 0x280;
    uint256 constant S_ID_I_OFFSET = 0x2a0;
    uint256 constant S_SIGMA_I_OFFSET = 0x2c0;

    function eval_permutations_at_challenge(
        types.lpc_params_type memory lpc_params,
        types.redshift_local_variables_calldata memory local_vars,
        uint256 column_polynomials_values_i
    ) internal pure {
        assembly {
            let modulus := mload(lpc_params)
            mstore(
                add(local_vars, G_OFFSET),
                mulmod(
                    mload(add(local_vars, G_OFFSET)),
                    // column_polynomials_values[i] + beta * S_id[i].evaluate(challenge) + gamma
                    addmod(
                        // column_polynomials_values[i]
                        column_polynomials_values_i,
                        // beta * S_id[i].evaluate(challenge) + gamma
                        addmod(
                            // beta * S_id[i].evaluate(challenge)
                            mulmod(
                                // beta
                                mload(add(local_vars, BETA_OFFSET)),
                                // S_id[i].evaluate(challenge)
                                mload(add(local_vars, S_ID_I_OFFSET)),
                                modulus
                            ),
                            // gamma
                            mload(add(local_vars, GAMMA_OFFSET)),
                            modulus
                        ),
                        modulus
                    ),
                    modulus
                )
            )
            mstore(
                add(local_vars, H_OFFSET),
                mulmod(
                    mload(add(local_vars, H_OFFSET)),
                    // column_polynomials_values[i] + beta * S_sigma[i].evaluate(challenge) + gamma
                    addmod(
                        // column_polynomials_values[i]
                        column_polynomials_values_i,
                        // beta * S_sigma[i].evaluate(challenge) + gamma
                        addmod(
                            // beta * S_sigma[i].evaluate(challenge)
                            mulmod(
                                // beta
                                mload(add(local_vars, BETA_OFFSET)),
                                // S_sigma[i].evaluate(challenge)
                                mload(add(local_vars, S_SIGMA_I_OFFSET)),
                                modulus
                            ),
                            // gamma
                            mload(add(local_vars, GAMMA_OFFSET)),
                            modulus
                        ),
                        modulus
                    ),
                    modulus
                )
            )
        }
    }

    function verify_eval_be(
        bytes calldata blob,
        types.transcript_data memory tr_state,
        types.redshift_proof_map_calldata memory proof_map,
        types.lpc_params_type memory lpc_params,
        types.redshift_common_data memory common_data,
        types.redshift_local_variables_calldata memory local_vars
    ) internal pure returns (uint256[] memory F) {
        local_vars.beta = transcript.get_field_challenge(
            tr_state,
            lpc_params.modulus
        );
        local_vars.gamma = transcript.get_field_challenge(
            tr_state,
            lpc_params.modulus
        );
        transcript.update_transcript_b32_by_offset_calldata(
            tr_state,
            blob,
            proof_map.v_perm_commitment_offset +
                basic_marshalling_calldata.LENGTH_OCTETS
        );

        local_vars.len = basic_marshalling_calldata.get_length(
            blob,
            proof_map.eval_proof_id_permutation_offset
        );
        require(
            local_vars.len ==
                basic_marshalling_calldata.get_length(
                    blob,
                    proof_map.eval_proof_sigma_permutation_offset
                ),
            "id_permutation length is not equal to sigma_permutation length!"
        );
        local_vars.tmp1 = basic_marshalling_calldata.get_length(
            blob,
            proof_map.eval_proof_witness_offset
        );
        local_vars.g = 1;
        local_vars.h = 1;
        local_vars.tmp2 =
            proof_map.eval_proof_id_permutation_offset +
            basic_marshalling_calldata.LENGTH_OCTETS;
        local_vars.tmp3 =
            proof_map.eval_proof_sigma_permutation_offset +
            basic_marshalling_calldata.LENGTH_OCTETS;
        for (
            local_vars.idx1 = 0;
            local_vars.idx1 < local_vars.len;
            local_vars.idx1++
        ) {
            for (
                local_vars.idx2 = 0;
                local_vars.idx2 <
                common_data.columns_rotations[local_vars.idx1].length;
                local_vars.idx2++
            ) {
                if (
                    common_data.columns_rotations[local_vars.idx1][
                        local_vars.idx2
                    ] == 0
                ) {
                    local_vars.zero_index = local_vars.idx2;
                }
            }

            local_vars.S_id_i = lpc_verifier_calldata.get_z_i_from_proof_be(
                blob,
                local_vars.tmp2,
                0
            );
            local_vars.tmp2 = lpc_verifier_calldata.skip_proof_be(
                blob,
                local_vars.tmp2
            );

            local_vars.S_sigma_i = lpc_verifier_calldata.get_z_i_from_proof_be(
                blob,
                local_vars.tmp3,
                0
            );
            local_vars.tmp3 = lpc_verifier_calldata.skip_proof_be(
                blob,
                local_vars.tmp3
            );

            if (local_vars.idx1 < local_vars.tmp1) {
                local_vars.offset = lpc_verifier_calldata
                    .skip_n_proofs_in_vector_be(
                        blob,
                        proof_map.eval_proof_witness_offset,
                        local_vars.idx1
                    );
                eval_permutations_at_challenge(
                    lpc_params,
                    local_vars,
                    lpc_verifier_calldata.get_z_i_from_proof_be(
                        blob,
                        local_vars.offset,
                        local_vars.zero_index
                    )
                );
            } else if (
                local_vars.idx1 <
                local_vars.tmp1 +
                    basic_marshalling_calldata.get_length(
                        blob,
                        proof_map.eval_proof_public_input_offset
                    )
            ) {
                local_vars.offset = lpc_verifier_calldata
                    .skip_n_proofs_in_vector_be(
                        blob,
                        proof_map.eval_proof_public_input_offset,
                        local_vars.idx1 - local_vars.tmp1
                    );
                eval_permutations_at_challenge(
                    lpc_params,
                    local_vars,
                    lpc_verifier_calldata.get_z_i_from_proof_be(
                        blob,
                        local_vars.offset,
                        local_vars.zero_index
                    )
                );
            } else {
                local_vars.offset =
                    local_vars.idx1 -
                    local_vars.tmp1 -
                    basic_marshalling_calldata.get_length(
                        blob,
                        proof_map.eval_proof_public_input_offset
                    );
                local_vars.offset = lpc_verifier_calldata
                    .skip_n_proofs_in_vector_be(
                        blob,
                        proof_map.eval_proof_constant_offset,
                        local_vars.offset
                    );
                eval_permutations_at_challenge(
                    lpc_params,
                    local_vars,
                    lpc_verifier_calldata.get_z_i_from_proof_be(
                        blob,
                        local_vars.offset,
                        local_vars.zero_index
                    )
                );
            }
        }

        local_vars.perm_polynomial_value = lpc_verifier_calldata
            .get_z_i_from_proof_be(
                blob,
                proof_map.eval_proof_permutation_offset +
                    basic_marshalling_calldata.LENGTH_OCTETS,
                0
            );
        local_vars.perm_polynomial_shifted_value = lpc_verifier_calldata
            .get_z_i_from_proof_be(
                blob,
                proof_map.eval_proof_permutation_offset +
                    basic_marshalling_calldata.LENGTH_OCTETS,
                1
            );
        local_vars.q_last_eval = lpc_verifier_calldata.get_z_i_from_proof_be(
            blob,
            proof_map.eval_proof_special_selectors_offset +
                basic_marshalling_calldata.LENGTH_OCTETS,
            0
        );
        local_vars.q_blind_eval = lpc_verifier_calldata.get_z_i_from_proof_be(
            blob,
            lpc_verifier_calldata.skip_proof_be(
                blob,
                proof_map.eval_proof_special_selectors_offset +
                    basic_marshalling_calldata.LENGTH_OCTETS
            ),
            0
        );

        F = new uint256[](ARGUMENT_SIZE);
        local_vars.challenge = basic_marshalling_calldata.get_uint256_be(
            blob,
            proof_map.eval_proof_offset
        );
        assembly {
            let modulus := mload(lpc_params)

            // F[0]
            switch mload(add(local_vars, CHALLENGE_OFFSET))
            case 1 {
                mstore(
                    add(F, 0x20),
                    // preprocessed_data.common_data.lagrange_0.evaluate(challenge) *
                    //  (one - perm_polynomial_value)
                    addmod(
                        1,
                        // one - perm_polynomial_value
                        sub(
                            modulus,
                            mload(add(local_vars, PERM_POLYNOMIAL_VALUE_OFFSET))
                        ),
                        modulus
                    )
                )
            }
            default {
                mstore(add(F, 0x20), 0)
            }

            // F[1]
            mstore(
                add(F, 0x40),
                // (one - preprocessed_data.q_last.evaluate(challenge) -
                //  preprocessed_data.q_blind.evaluate(challenge)) *
                //  (perm_polynomial_shifted_value * h - perm_polynomial_value * g)
                mulmod(
                    // one - preprocessed_data.q_last.evaluate(challenge) -
                    //  preprocessed_data.q_blind.evaluate(challenge)
                    addmod(
                        1,
                        // -preprocessed_data.q_last.evaluate(challenge) - preprocessed_data.q_blind.evaluate(challenge)
                        addmod(
                            // -preprocessed_data.q_last.evaluate(challenge)
                            sub(
                                modulus,
                                mload(add(local_vars, Q_LAST_EVAL_OFFSET))
                            ),
                            // -preprocessed_data.q_blind.evaluate(challenge)
                            sub(
                                modulus,
                                mload(add(local_vars, Q_BLIND_EVAL_OFFSET))
                            ),
                            modulus
                        ),
                        modulus
                    ),
                    // perm_polynomial_shifted_value * h - perm_polynomial_value * g
                    addmod(
                        // perm_polynomial_shifted_value * h
                        mulmod(
                            // perm_polynomial_shifted_value
                            mload(
                                add(
                                    local_vars,
                                    PERM_POLYNOMIAL_SHIFTED_VALUE_OFFSET
                                )
                            ),
                            // h
                            mload(add(local_vars, H_OFFSET)),
                            modulus
                        ),
                        // - perm_polynomial_value * g
                        sub(
                            modulus,
                            mulmod(
                                // perm_polynomial_value
                                mload(
                                    add(
                                        local_vars,
                                        PERM_POLYNOMIAL_VALUE_OFFSET
                                    )
                                ),
                                // g
                                mload(add(local_vars, G_OFFSET)),
                                modulus
                            )
                        ),
                        modulus
                    ),
                    modulus
                )
            )

            // F[2]
            mstore(
                add(F, 0x60),
                // preprocessed_data.q_last.evaluate(challenge) *
                //  (perm_polynomial_value.squared() - perm_polynomial_value)
                mulmod(
                    // preprocessed_data.q_last.evaluate(challenge)
                    mload(add(local_vars, Q_LAST_EVAL_OFFSET)),
                    // perm_polynomial_value.squared() - perm_polynomial_value
                    addmod(
                        // perm_polynomial_value.squared()
                        mulmod(
                            // perm_polynomial_value
                            mload(
                                add(local_vars, PERM_POLYNOMIAL_VALUE_OFFSET)
                            ),
                            // perm_polynomial_value
                            mload(
                                add(local_vars, PERM_POLYNOMIAL_VALUE_OFFSET)
                            ),
                            modulus
                        ),
                        // -perm_polynomial_value
                        sub(
                            modulus,
                            mload(add(local_vars, PERM_POLYNOMIAL_VALUE_OFFSET))
                        ),
                        modulus
                    ),
                    modulus
                )
            )
        }
    }
}
