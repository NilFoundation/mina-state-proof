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
import "../commitments/lpc_verifier_calldata.sol";

library unified_addition_component_calldata {
    uint256 constant WITNESSES_N = 11;
    uint256 constant WITNESSES_TOTAL_N = 11;
    uint256 constant GATES_N = 1;

    uint256 constant THETA_OFFSET = 0x20;
    uint256 constant CONSTRAINT_EVAL_OFFSET = 0x40;
    uint256 constant GATE_EVAL_OFFSET = 0x60;
    uint256 constant WITNESS_EVALUATIONS_OFFSET = 0x80;
    uint256 constant SELECTOR_EVALUATIONS_OFFSET = 0xa0;

    // TODO: columns_rotations could be hard-coded
    function evaluate_gates_be(
        bytes calldata blob,
        types.gate_argument_local_vars memory gate_params,
        int256[][] memory columns_rotations
    ) internal pure returns (uint256 gates_evaluation) {
        // TODO: check witnesses number in proof

        gate_params.witness_evaluations = new uint256[][](WITNESSES_N);
        gate_params.offset =
            gate_params.eval_proof_witness_offset +
            basic_marshalling_calldata.LENGTH_OCTETS;
        for (uint256 i = 0; i < WITNESSES_N; i++) {
            gate_params.witness_evaluations[i] = new uint256[](
                columns_rotations[i].length
            );
            for (uint256 j = 0; j < columns_rotations[i].length; j++) {
                gate_params.witness_evaluations[i][j] = lpc_verifier_calldata
                    .get_z_i_from_proof_be(blob, gate_params.offset, j);
            }
            gate_params.offset = lpc_verifier_calldata.skip_proof_be(
                blob,
                gate_params.offset
            );
        }
        gate_params.selector_evaluations = new uint256[](GATES_N);
        gate_params.offset =
            gate_params.eval_proof_selector_offset +
            basic_marshalling_calldata.LENGTH_OCTETS;
        for (uint256 i = 0; i < GATES_N; i++) {
            gate_params.selector_evaluations[i] = lpc_verifier_calldata
                .get_z_i_from_proof_be(blob, gate_params.offset, 0);
            gate_params.offset = lpc_verifier_calldata.skip_proof_be(
                blob,
                gate_params.offset
            );
        }

        assembly {
            let modulus := mload(gate_params)
            let theta_acc := 1
            mstore(add(gate_params, GATE_EVAL_OFFSET), 0)

            function get_W_i_by_rotation_idx(idx, rot_idx, ptr) -> result {
                result := mload(
                    add(
                        add(mload(add(add(ptr, 0x20), mul(0x20, idx))), 0x20),
                        mul(0x20, rot_idx)
                    )
                )
            }

            function get_selector_i(idx, ptr) -> result {
                result := mload(add(add(ptr, 0x20), mul(0x20, idx)))
            }

            //==========================================================================================================
            // 1. w_7 * (w_2 - w_0)
            mstore(
                add(gate_params, CONSTRAINT_EVAL_OFFSET),
                mulmod(
                    // w_7
                    get_W_i_by_rotation_idx(
                        7,
                        0,
                        mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))
                    ),
                    // w_2 - w_0
                    addmod(
                        // w_2
                        get_W_i_by_rotation_idx(
                            2,
                            0,
                            mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))
                        ),
                        // -w_0
                        sub(
                            modulus,
                            get_W_i_by_rotation_idx(
                                0,
                                0,
                                mload(
                                    add(gate_params, WITNESS_EVALUATIONS_OFFSET)
                                )
                            )
                        ),
                        modulus
                    ),
                    modulus
                )
            )
            // gate_evaluation += constraint_eval * theta_acc
            mstore(
                add(gate_params, GATE_EVAL_OFFSET),
                addmod(
                    mload(add(gate_params, GATE_EVAL_OFFSET)),
                    mulmod(
                        mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),
                        theta_acc,
                        modulus
                    ),
                    modulus
                )
            )
            // theta_acc *= theta
            theta_acc := mulmod(
                theta_acc,
                mload(add(gate_params, THETA_OFFSET)),
                modulus
            )

            //==========================================================================================================
            // 2. (w_2 - w_0) * w_10 - (1 - w_7)
            mstore(
                add(gate_params, CONSTRAINT_EVAL_OFFSET),
                addmod(
                    // (w_2 - w_0) * w_10
                    mulmod(
                        // (w_2 - w_0)
                        addmod(
                            // w_2
                            get_W_i_by_rotation_idx(
                                2,
                                0,
                                mload(
                                    add(gate_params, WITNESS_EVALUATIONS_OFFSET)
                                )
                            ),
                            // -w_0
                            sub(
                                modulus,
                                get_W_i_by_rotation_idx(
                                    0,
                                    0,
                                    mload(
                                        add(
                                            gate_params,
                                            WITNESS_EVALUATIONS_OFFSET
                                        )
                                    )
                                )
                            ),
                            modulus
                        ),
                        // w_10
                        get_W_i_by_rotation_idx(
                            10,
                            0,
                            mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))
                        ),
                        modulus
                    ),
                    // -(1 - w_7)
                    sub(
                        modulus,
                        addmod(
                            1,
                            // -w_7
                            sub(
                                modulus,
                                get_W_i_by_rotation_idx(
                                    7,
                                    0,
                                    mload(
                                        add(
                                            gate_params,
                                            WITNESS_EVALUATIONS_OFFSET
                                        )
                                    )
                                )
                            ),
                            modulus
                        )
                    ),
                    modulus
                )
            )
            // gate_evaluation += constraint_eval * theta_acc
            mstore(
                add(gate_params, GATE_EVAL_OFFSET),
                addmod(
                    mload(add(gate_params, GATE_EVAL_OFFSET)),
                    mulmod(
                        mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),
                        theta_acc,
                        modulus
                    ),
                    modulus
                )
            )
            // theta_acc *= theta
            theta_acc := mulmod(
                theta_acc,
                mload(add(gate_params, THETA_OFFSET)),
                modulus
            )

            //==========================================================================================================
            // 3. w_7 * (2 * w_8 * w_1 - 3 * w_0 * w_0) + (1 - w_7) * ((w_2 - w_0) * w_8 - (w_3 - w_1))
            mstore(
                add(gate_params, CONSTRAINT_EVAL_OFFSET),
                addmod(
                    // w_7 * (2 * w_8 * w_1 - 3 * w_0 * w_0)
                    mulmod(
                        // w_7
                        get_W_i_by_rotation_idx(
                            7,
                            0,
                            mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))
                        ),
                        // (2 * w_8 * w_1 - 3 * w_0 * w_0)
                        addmod(
                            // 2 * w_8 * w_1
                            mulmod(
                                2,
                                // w_8 * w_1
                                mulmod(
                                    // w_8
                                    get_W_i_by_rotation_idx(
                                        8,
                                        0,
                                        mload(
                                            add(
                                                gate_params,
                                                WITNESS_EVALUATIONS_OFFSET
                                            )
                                        )
                                    ),
                                    // w_1
                                    get_W_i_by_rotation_idx(
                                        1,
                                        0,
                                        mload(
                                            add(
                                                gate_params,
                                                WITNESS_EVALUATIONS_OFFSET
                                            )
                                        )
                                    ),
                                    modulus
                                ),
                                modulus
                            ),
                            // 3 * w_0 * w_0
                            mulmod(
                                3,
                                // w_0 * w_0
                                mulmod(
                                    // w_0
                                    get_W_i_by_rotation_idx(
                                        0,
                                        0,
                                        mload(
                                            add(
                                                gate_params,
                                                WITNESS_EVALUATIONS_OFFSET
                                            )
                                        )
                                    ),
                                    // w_0
                                    get_W_i_by_rotation_idx(
                                        0,
                                        0,
                                        mload(
                                            add(
                                                gate_params,
                                                WITNESS_EVALUATIONS_OFFSET
                                            )
                                        )
                                    ),
                                    modulus
                                ),
                                modulus
                            ),
                            modulus
                        ),
                        modulus
                    ),
                    // (1 - w_7) * ((w_2 - w_0) * w_8 - (w_3 - w_1))
                    mulmod(
                        // 1 - w_7
                        addmod(
                            1,
                            // -w_7
                            sub(
                                modulus,
                                get_W_i_by_rotation_idx(
                                    7,
                                    0,
                                    mload(
                                        add(
                                            gate_params,
                                            WITNESS_EVALUATIONS_OFFSET
                                        )
                                    )
                                )
                            ),
                            modulus
                        ),
                        // (w_2 - w_0) * w_8 - (w_3 - w_1)
                        addmod(
                            // (w_2 - w_0) * w_8
                            mulmod(
                                //w_2 - w_0
                                addmod(
                                    // w_2
                                    get_W_i_by_rotation_idx(
                                        2,
                                        0,
                                        mload(
                                            add(
                                                gate_params,
                                                WITNESS_EVALUATIONS_OFFSET
                                            )
                                        )
                                    ),
                                    // -w_0
                                    sub(
                                        modulus,
                                        get_W_i_by_rotation_idx(
                                            0,
                                            0,
                                            mload(
                                                add(
                                                    gate_params,
                                                    WITNESS_EVALUATIONS_OFFSET
                                                )
                                            )
                                        )
                                    ),
                                    modulus
                                ),
                                // w_8
                                get_W_i_by_rotation_idx(
                                    8,
                                    0,
                                    mload(
                                        add(
                                            gate_params,
                                            WITNESS_EVALUATIONS_OFFSET
                                        )
                                    )
                                ),
                                modulus
                            ),
                            // -(w_3 - w_1)
                            sub(
                                modulus,
                                // w_3 - w_1
                                addmod(
                                    // w_3
                                    get_W_i_by_rotation_idx(
                                        3,
                                        0,
                                        mload(
                                            add(
                                                gate_params,
                                                WITNESS_EVALUATIONS_OFFSET
                                            )
                                        )
                                    ),
                                    // -w_1
                                    sub(
                                        modulus,
                                        get_W_i_by_rotation_idx(
                                            1,
                                            0,
                                            mload(
                                                add(
                                                    gate_params,
                                                    WITNESS_EVALUATIONS_OFFSET
                                                )
                                            )
                                        )
                                    ),
                                    modulus
                                )
                            ),
                            modulus
                        ),
                        modulus
                    ),
                    modulus
                )
            )
            // gate_evaluation += constraint_eval * theta_acc
            mstore(
                add(gate_params, GATE_EVAL_OFFSET),
                addmod(
                    mload(add(gate_params, GATE_EVAL_OFFSET)),
                    mulmod(
                        mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),
                        theta_acc,
                        modulus
                    ),
                    modulus
                )
            )
            // theta_acc *= theta
            theta_acc := mulmod(
                theta_acc,
                mload(add(gate_params, THETA_OFFSET)),
                modulus
            )

            //==========================================================================================================
            // 4. w_8 * w_8 - (w_0 + w_2 + w_4)
            mstore(
                add(gate_params, CONSTRAINT_EVAL_OFFSET),
                addmod(
                    // w_8 * w_8
                    mulmod(
                        // w_8
                        get_W_i_by_rotation_idx(
                            8,
                            0,
                            mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))
                        ),
                        // w_8
                        get_W_i_by_rotation_idx(
                            8,
                            0,
                            mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))
                        ),
                        modulus
                    ),
                    // -(w_0 + w_2 + w_4)
                    sub(
                        modulus,
                        // w_0 + w_2 + w_4
                        addmod(
                            // w_0 + w_2
                            addmod(
                                // w_0
                                get_W_i_by_rotation_idx(
                                    0,
                                    0,
                                    mload(
                                        add(
                                            gate_params,
                                            WITNESS_EVALUATIONS_OFFSET
                                        )
                                    )
                                ),
                                // w_2
                                get_W_i_by_rotation_idx(
                                    2,
                                    0,
                                    mload(
                                        add(
                                            gate_params,
                                            WITNESS_EVALUATIONS_OFFSET
                                        )
                                    )
                                ),
                                modulus
                            ),
                            // w_4
                            get_W_i_by_rotation_idx(
                                4,
                                0,
                                mload(
                                    add(gate_params, WITNESS_EVALUATIONS_OFFSET)
                                )
                            ),
                            modulus
                        )
                    ),
                    modulus
                )
            )
            // gate_evaluation += constraint_eval * theta_acc
            mstore(
                add(gate_params, GATE_EVAL_OFFSET),
                addmod(
                    mload(add(gate_params, GATE_EVAL_OFFSET)),
                    mulmod(
                        mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),
                        theta_acc,
                        modulus
                    ),
                    modulus
                )
            )
            // theta_acc *= theta
            theta_acc := mulmod(
                theta_acc,
                mload(add(gate_params, THETA_OFFSET)),
                modulus
            )

            //==========================================================================================================
            // 5. w_5 - (w_8 * (w_0 - w_4) - w_1)
            mstore(
                add(gate_params, CONSTRAINT_EVAL_OFFSET),
                addmod(
                    // w_5
                    get_W_i_by_rotation_idx(
                        5,
                        0,
                        mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))
                    ),
                    // -(w_8 * (w_0 - w_4) - w_1)
                    sub(
                        modulus,
                        // w_8 * (w_0 - w_4) - w_1
                        addmod(
                            // w_8 * (w_0 - w_4)
                            mulmod(
                                // w_8
                                get_W_i_by_rotation_idx(
                                    8,
                                    0,
                                    mload(
                                        add(
                                            gate_params,
                                            WITNESS_EVALUATIONS_OFFSET
                                        )
                                    )
                                ),
                                // w_0 - w_4
                                addmod(
                                    // w_0
                                    get_W_i_by_rotation_idx(
                                        0,
                                        0,
                                        mload(
                                            add(
                                                gate_params,
                                                WITNESS_EVALUATIONS_OFFSET
                                            )
                                        )
                                    ),
                                    // -w_4
                                    sub(
                                        modulus,
                                        get_W_i_by_rotation_idx(
                                            4,
                                            0,
                                            mload(
                                                add(
                                                    gate_params,
                                                    WITNESS_EVALUATIONS_OFFSET
                                                )
                                            )
                                        )
                                    ),
                                    modulus
                                ),
                                modulus
                            ),
                            // -w_1
                            sub(
                                modulus,
                                get_W_i_by_rotation_idx(
                                    1,
                                    0,
                                    mload(
                                        add(
                                            gate_params,
                                            WITNESS_EVALUATIONS_OFFSET
                                        )
                                    )
                                )
                            ),
                            modulus
                        )
                    ),
                    modulus
                )
            )
            // gate_evaluation += constraint_eval * theta_acc
            mstore(
                add(gate_params, GATE_EVAL_OFFSET),
                addmod(
                    mload(add(gate_params, GATE_EVAL_OFFSET)),
                    mulmod(
                        mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),
                        theta_acc,
                        modulus
                    ),
                    modulus
                )
            )
            // theta_acc *= theta
            theta_acc := mulmod(
                theta_acc,
                mload(add(gate_params, THETA_OFFSET)),
                modulus
            )

            //==========================================================================================================
            // 6. (w_3 - w_1) * (w_7 - w_6)
            mstore(
                add(gate_params, CONSTRAINT_EVAL_OFFSET),
                mulmod(
                    // w_3 - w_1
                    addmod(
                        // w_3
                        get_W_i_by_rotation_idx(
                            3,
                            0,
                            mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))
                        ),
                        // -w_1
                        sub(
                            modulus,
                            get_W_i_by_rotation_idx(
                                1,
                                0,
                                mload(
                                    add(gate_params, WITNESS_EVALUATIONS_OFFSET)
                                )
                            )
                        ),
                        modulus
                    ),
                    // w_7 - w_6
                    addmod(
                        // w_7
                        get_W_i_by_rotation_idx(
                            7,
                            0,
                            mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))
                        ),
                        // -w_6
                        sub(
                            modulus,
                            get_W_i_by_rotation_idx(
                                6,
                                0,
                                mload(
                                    add(gate_params, WITNESS_EVALUATIONS_OFFSET)
                                )
                            )
                        ),
                        modulus
                    ),
                    modulus
                )
            )
            // gate_evaluation += constraint_eval * theta_acc
            mstore(
                add(gate_params, GATE_EVAL_OFFSET),
                addmod(
                    mload(add(gate_params, GATE_EVAL_OFFSET)),
                    mulmod(
                        mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),
                        theta_acc,
                        modulus
                    ),
                    modulus
                )
            )
            // theta_acc *= theta
            theta_acc := mulmod(
                theta_acc,
                mload(add(gate_params, THETA_OFFSET)),
                modulus
            )

            //==========================================================================================================
            // 7. (w_3 - w_1) * w_9 - w_6
            mstore(
                add(gate_params, CONSTRAINT_EVAL_OFFSET),
                addmod(
                    // (w_3 - w_1) * w_9
                    mulmod(
                        // w_3 - w_1
                        addmod(
                            // w_3
                            get_W_i_by_rotation_idx(
                                3,
                                0,
                                mload(
                                    add(gate_params, WITNESS_EVALUATIONS_OFFSET)
                                )
                            ),
                            // -w_1
                            sub(
                                modulus,
                                get_W_i_by_rotation_idx(
                                    1,
                                    0,
                                    mload(
                                        add(
                                            gate_params,
                                            WITNESS_EVALUATIONS_OFFSET
                                        )
                                    )
                                )
                            ),
                            modulus
                        ),
                        // w_9
                        get_W_i_by_rotation_idx(
                            9,
                            0,
                            mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))
                        ),
                        modulus
                    ),
                    // -w_6
                    sub(
                        modulus,
                        get_W_i_by_rotation_idx(
                            6,
                            0,
                            mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))
                        )
                    ),
                    modulus
                )
            )
            // gate_evaluation += constraint_eval * theta_acc
            mstore(
                add(gate_params, GATE_EVAL_OFFSET),
                addmod(
                    mload(add(gate_params, GATE_EVAL_OFFSET)),
                    mulmod(
                        mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),
                        theta_acc,
                        modulus
                    ),
                    modulus
                )
            )
            // theta_acc *= theta
            theta_acc := mulmod(
                theta_acc,
                mload(add(gate_params, THETA_OFFSET)),
                modulus
            )

            //==========================================================================================================
            mstore(
                add(gate_params, GATE_EVAL_OFFSET),
                mulmod(
                    mload(add(gate_params, GATE_EVAL_OFFSET)),
                    get_selector_i(
                        0,
                        mload(add(gate_params, SELECTOR_EVALUATIONS_OFFSET))
                    ),
                    modulus
                )
            )

            gates_evaluation := addmod(
                gates_evaluation,
                mload(add(gate_params, GATE_EVAL_OFFSET)),
                modulus
            )
            mstore(add(gate_params, GATE_EVAL_OFFSET), 0)
        }
    }
}
