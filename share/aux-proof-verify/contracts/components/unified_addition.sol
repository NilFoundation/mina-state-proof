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

library unified_addition_component {
    uint256 constant WITNESS_ASSIGNMENTS_N = 11;
    uint256 constant GATES_N = 1;

    function evaluate_gates_be(
        uint256[] memory assignment_pointers,
        types.gate_eval_params memory params
    ) internal pure returns (uint256 gate_evaluation) {
        require(assignment_pointers.length >= WITNESS_ASSIGNMENTS_N);
        require(params.selector_evaluations_ptrs.length >= GATES_N);

        assembly {
            gate_evaluation := 0
            let modulus := mload(params)
            let theta_acc := mload(add(params, 0x20))
            let theta := mload(add(params, 0x40))

            //==========================================================================================================
            // 1. w_7 * (w_2 - w_0)
            let constraint_eval := mulmod(
                // w_7
                mload(mload(add(assignment_pointers, 0x100))),
                // w_2 - w_0
                addmod(
                    // w_2
                    mload(mload(add(assignment_pointers, 0x60))),
                    // -w_0
                    sub(modulus, mload(mload(add(assignment_pointers, 0x20)))),
                    modulus
                ),
                modulus
            )
            // gate_evaluation += constraint_eval * theta_acc
            gate_evaluation := addmod(
                gate_evaluation,
                mulmod(constraint_eval, theta_acc, modulus),
                modulus
            )
            // theta_acc *= theta
            theta_acc := mulmod(theta_acc, theta, modulus)

            //==========================================================================================================
            // 2. (w_2 - w_0) * w_10 - (1 - w_7)
            constraint_eval := addmod(
                // (w_2 - w_0) * w_10
                mulmod(
                    // (w_2 - w_0)
                    addmod(
                        // w_2
                        mload(mload(add(assignment_pointers, 0x60))),
                        // -w_0
                        sub(
                            modulus,
                            mload(mload(add(assignment_pointers, 0x20)))
                        ),
                        modulus
                    ),
                    // w_10
                    mload(mload(add(assignment_pointers, 0x160))),
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
                            mload(mload(add(assignment_pointers, 0x100)))
                        ),
                        modulus
                    )
                ),
                modulus
            )
            // gate_evaluation += constraint_2_eval * theta_acc
            gate_evaluation := addmod(
                gate_evaluation,
                mulmod(constraint_eval, theta_acc, modulus),
                modulus
            )
            // theta_acc *= theta
            theta_acc := mulmod(theta_acc, theta, modulus)

            //==========================================================================================================
            // 3. w_7 * (2 * w_8 * w_1 - 3 * w_0 * w_0) + (1 - w_7) * ((w_2 - w_0) * w_8 - (w_3 - w_1))
            constraint_eval := addmod(
                // w_7 * (2 * w_8 * w_1 - 3 * w_0 * w_0)
                mulmod(
                    // w_7
                    mload(mload(add(assignment_pointers, 0x100))),
                    // (2 * w_8 * w_1 - 3 * w_0 * w_0)
                    addmod(
                        // 2 * w_8 * w_1
                        mulmod(
                            2,
                            // w_8 * w_1
                            mulmod(
                                // w_8
                                mload(mload(add(assignment_pointers, 0x120))),
                                // w_1
                                mload(mload(add(assignment_pointers, 0x40))),
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
                                mload(mload(add(assignment_pointers, 0x20))),
                                // w_0
                                mload(mload(add(assignment_pointers, 0x20))),
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
                            mload(mload(add(assignment_pointers, 0x100)))
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
                                mload(mload(add(assignment_pointers, 0x60))),
                                // -w_0
                                sub(
                                    modulus,
                                    mload(mload(add(assignment_pointers, 0x20)))
                                ),
                                modulus
                            ),
                            // w_8
                            mload(mload(add(assignment_pointers, 0x120))),
                            modulus
                        ),
                        // -(w_3 - w_1)
                        sub(
                            modulus,
                            // w_3 - w_1
                            addmod(
                                // w_3
                                mload(mload(add(assignment_pointers, 0x80))),
                                // -w_1
                                sub(
                                    modulus,
                                    mload(mload(add(assignment_pointers, 0x40)))
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
            // gate_evaluation += constraint_eval * theta_acc
            gate_evaluation := addmod(
                gate_evaluation,
                mulmod(constraint_eval, theta_acc, modulus),
                modulus
            )
            // theta_acc *= theta
            theta_acc := mulmod(theta_acc, theta, modulus)

            //==========================================================================================================
            // 4. w_8 * w_8 - (w_0 + w_2 + w_4)
            constraint_eval := addmod(
                // w_8 * w_8
                mulmod(
                    // w_8
                    mload(mload(add(assignment_pointers, 0x120))),
                    // w_8
                    mload(mload(add(assignment_pointers, 0x120))),
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
                            mload(mload(add(assignment_pointers, 0x20))),
                            // w_2
                            mload(mload(add(assignment_pointers, 0x60))),
                            modulus
                        ),
                        // w_4
                        mload(mload(add(assignment_pointers, 0xa0))),
                        modulus
                    )
                ),
                modulus
            )
            // gate_evaluation += constraint_eval * theta_acc
            gate_evaluation := addmod(
                gate_evaluation,
                mulmod(constraint_eval, theta_acc, modulus),
                modulus
            )
            // theta_acc *= theta
            theta_acc := mulmod(theta_acc, theta, modulus)

            //==========================================================================================================
            // 5. w_5 - (w_8 * (w_0 - w_4) - w_1)
            constraint_eval := addmod(
                // w_5
                mload(mload(add(assignment_pointers, 0xc0))),
                // -(w_8 * (w_0 - w_4) - w_1)
                sub(
                    modulus,
                    // w_8 * (w_0 - w_4) - w_1
                    addmod(
                        // w_8 * (w_0 - w_4)
                        mulmod(
                            // w_8
                            mload(mload(add(assignment_pointers, 0x120))),
                            // w_0 - w_4
                            addmod(
                                // w_0
                                mload(mload(add(assignment_pointers, 0x20))),
                                // -w_4
                                sub(
                                    modulus,
                                    mload(mload(add(assignment_pointers, 0xa0)))
                                ),
                                modulus
                            ),
                            modulus
                        ),
                        // -w_1
                        sub(
                            modulus,
                            mload(mload(add(assignment_pointers, 0x40)))
                        ),
                        modulus
                    )
                ),
                modulus
            )
            // gate_evaluation += constraint_eval * theta_acc
            gate_evaluation := addmod(
                gate_evaluation,
                mulmod(constraint_eval, theta_acc, modulus),
                modulus
            )
            // theta_acc *= theta
            theta_acc := mulmod(theta_acc, theta, modulus)

            //==========================================================================================================
            // 6. (w_3 - w_1) * (w_7 - w_6)
            constraint_eval := mulmod(
                // w_3 - w_1
                addmod(
                    // w_3
                    mload(mload(add(assignment_pointers, 0x80))),
                    // -w_1
                    sub(modulus, mload(mload(add(assignment_pointers, 0x40)))),
                    modulus
                ),
                // w_7 - w_6
                addmod(
                    // w_7
                    mload(mload(add(assignment_pointers, 0x100))),
                    // -w_6
                    sub(modulus, mload(mload(add(assignment_pointers, 0xe0)))),
                    modulus
                ),
                modulus
            )
            // gate_evaluation += constraint_eval * theta_acc
            gate_evaluation := addmod(
                gate_evaluation,
                mulmod(constraint_eval, theta_acc, modulus),
                modulus
            )
            // theta_acc *= theta
            theta_acc := mulmod(theta_acc, theta, modulus)

            //==========================================================================================================
            // 7. (w_3 - w_1) * w_9 - w_6
            constraint_eval := addmod(
                // (w_3 - w_1) * w_9
                mulmod(
                    // w_3 - w_1
                    addmod(
                        // w_3
                        mload(mload(add(assignment_pointers, 0x80))),
                        // -w_1
                        sub(
                            modulus,
                            mload(mload(add(assignment_pointers, 0x40)))
                        ),
                        modulus
                    ),
                    // w_9
                    mload(mload(add(assignment_pointers, 0x140))),
                    modulus
                ),
                // -w_6
                sub(modulus, mload(mload(add(assignment_pointers, 0xe0)))),
                modulus
            )
            // gate_evaluation += constraint_eval * theta_acc
            gate_evaluation := addmod(
                gate_evaluation,
                mulmod(constraint_eval, theta_acc, modulus),
                modulus
            )
            // theta_acc *= theta
            theta_acc := mulmod(theta_acc, theta, modulus)
            mstore(add(params, 0x20), theta_acc)

            //==========================================================================================================
            gate_evaluation := mulmod(
                gate_evaluation,
                mload(mload(add(mload(add(params, 0x60)), 0x20))),
                modulus
            )
        }
    }
}
