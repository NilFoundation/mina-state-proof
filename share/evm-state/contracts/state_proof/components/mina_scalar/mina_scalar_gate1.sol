// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

import "../../types.sol";
import "../../logging.sol";

// TODO: name component
library mina_scalar_gate1 {
    uint256 constant MODULUS_OFFSET = 0x0;
    uint256 constant THETA_OFFSET = 0x20;
    uint256 constant CONSTRAINT_EVAL_OFFSET = 0x40;
    uint256 constant GATE_EVAL_OFFSET = 0x60;
    uint256 constant WITNESS_EVALUATIONS_OFFSET_OFFSET = 0x80;
    uint256 constant SELECTOR_EVALUATIONS_OFFSET = 0xa0;
    uint256 constant EVAL_PROOF_WITNESS_OFFSET_OFFSET = 0xc0;
    uint256 constant EVAL_PROOF_SELECTOR_OFFSET_OFFSET = 0xe0;
    uint256 constant GATES_EVALUATION_OFFSET = 0x100;
    uint256 constant THETA_ACC_OFFSET = 0x120;
    uint256 constant SELECTOR_EVALUATIONS_OFFSET_OFFSET = 0x140;
    uint256 constant OFFSET_OFFSET = 0x160;
    uint256 constant WITNESS_EVALUATIONS_OFFSET = 0x180;
    uint256 constant CONSTANT_EVALUATIONS_OFFSET = 0x1a0;
    uint256 constant PUBLIC_INPUT_EVALUATIONS_OFFSET = 0x1c0;

    // TODO: columns_rotations could be hard-coded
    function evaluate_gate_be(
        types.gate_argument_local_vars memory gate_params,
        int256[][] memory columns_rotations
    ) external pure returns (uint256 gates_evaluation, uint256 theta_acc) {
        gates_evaluation = gate_params.gates_evaluation;
        theta_acc = gate_params.theta_acc;
        assembly {
            let modulus := mload(gate_params)
            mstore(add(gate_params, GATE_EVAL_OFFSET), 0)

            function get_eval_i_by_rotation_idx(idx, rot_idx, ptr) -> result {
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

            // TODO: insert generated code for gate argument evaluation here
            let x1 := add(gate_params, WITNESS_EVALUATIONS_OFFSET)
            let x2 := add(gate_params, CONSTRAINT_EVAL_OFFSET)
            mstore(add(gate_params, GATE_EVAL_OFFSET), 0)
            mstore(x2, 0)
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb,get_eval_i_by_rotation_idx(7,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),get_eval_i_by_rotation_idx(7,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x3,mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),get_eval_i_by_rotation_idx(7,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),get_eval_i_by_rotation_idx(7,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x6,mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),get_eval_i_by_rotation_idx(7,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff,mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),get_eval_i_by_rotation_idx(7,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe,mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),get_eval_i_by_rotation_idx(7,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),get_eval_i_by_rotation_idx(7,0, mload(x1)), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x2),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x2, 0)
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb,get_eval_i_by_rotation_idx(8,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),get_eval_i_by_rotation_idx(8,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x3,mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),get_eval_i_by_rotation_idx(8,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),get_eval_i_by_rotation_idx(8,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x6,mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),get_eval_i_by_rotation_idx(8,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff,mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),get_eval_i_by_rotation_idx(8,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe,mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),get_eval_i_by_rotation_idx(8,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),get_eval_i_by_rotation_idx(8,0, mload(x1)), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x2),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x2, 0)
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb,get_eval_i_by_rotation_idx(9,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),get_eval_i_by_rotation_idx(9,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x3,mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),get_eval_i_by_rotation_idx(9,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),get_eval_i_by_rotation_idx(9,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x6,mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),get_eval_i_by_rotation_idx(9,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff,mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),get_eval_i_by_rotation_idx(9,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe,mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),get_eval_i_by_rotation_idx(9,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),get_eval_i_by_rotation_idx(9,0, mload(x1)), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x2),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x2, 0)
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb,get_eval_i_by_rotation_idx(10,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),get_eval_i_by_rotation_idx(10,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x3,mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),get_eval_i_by_rotation_idx(10,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),get_eval_i_by_rotation_idx(10,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x6,mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),get_eval_i_by_rotation_idx(10,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff,mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),get_eval_i_by_rotation_idx(10,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe,mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),get_eval_i_by_rotation_idx(10,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),get_eval_i_by_rotation_idx(10,0, mload(x1)), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x2),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x2, 0)
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb,get_eval_i_by_rotation_idx(11,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),get_eval_i_by_rotation_idx(11,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x3,mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),get_eval_i_by_rotation_idx(11,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),get_eval_i_by_rotation_idx(11,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x6,mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),get_eval_i_by_rotation_idx(11,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff,mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),get_eval_i_by_rotation_idx(11,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe,mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),get_eval_i_by_rotation_idx(11,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),get_eval_i_by_rotation_idx(11,0, mload(x1)), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x2),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x2, 0)
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb,get_eval_i_by_rotation_idx(12,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),get_eval_i_by_rotation_idx(12,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x3,mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),get_eval_i_by_rotation_idx(12,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),get_eval_i_by_rotation_idx(12,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x6,mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),get_eval_i_by_rotation_idx(12,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff,mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),get_eval_i_by_rotation_idx(12,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe,mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),get_eval_i_by_rotation_idx(12,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),get_eval_i_by_rotation_idx(12,0, mload(x1)), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x2),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x2, 0)
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb,get_eval_i_by_rotation_idx(13,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),get_eval_i_by_rotation_idx(13,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x3,mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),get_eval_i_by_rotation_idx(13,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),get_eval_i_by_rotation_idx(13,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x6,mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),get_eval_i_by_rotation_idx(13,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff,mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),get_eval_i_by_rotation_idx(13,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe,mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),get_eval_i_by_rotation_idx(13,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),get_eval_i_by_rotation_idx(13,0, mload(x1)), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x2),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x2, 0)
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb,get_eval_i_by_rotation_idx(14,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),get_eval_i_by_rotation_idx(14,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x3,mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),get_eval_i_by_rotation_idx(14,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),get_eval_i_by_rotation_idx(14,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x6,mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),get_eval_i_by_rotation_idx(14,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff,mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),get_eval_i_by_rotation_idx(14,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe,mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),get_eval_i_by_rotation_idx(14,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),get_eval_i_by_rotation_idx(14,0, mload(x1)), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x2),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x2, 0)
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffff01,get_eval_i_by_rotation_idx(2,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffff16,get_eval_i_by_rotation_idx(7,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x140,mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),get_eval_i_by_rotation_idx(7,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffab,mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),get_eval_i_by_rotation_idx(7,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90affffff8b,get_eval_i_by_rotation_idx(8,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0xa0,mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),get_eval_i_by_rotation_idx(8,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffffd6,mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),get_eval_i_by_rotation_idx(8,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffffc6,get_eval_i_by_rotation_idx(9,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x50,mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),get_eval_i_by_rotation_idx(9,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffeb,mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),get_eval_i_by_rotation_idx(9,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffe3,get_eval_i_by_rotation_idx(10,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x28,mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),get_eval_i_by_rotation_idx(10,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffff6,mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),get_eval_i_by_rotation_idx(10,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffff2,get_eval_i_by_rotation_idx(11,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x14,mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),get_eval_i_by_rotation_idx(11,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90afffffffb,mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),get_eval_i_by_rotation_idx(11,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90afffffff9,get_eval_i_by_rotation_idx(12,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0xa,mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),get_eval_i_by_rotation_idx(12,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffffe,mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),get_eval_i_by_rotation_idx(12,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffffd,get_eval_i_by_rotation_idx(13,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x5,mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),get_eval_i_by_rotation_idx(13,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffff,mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),get_eval_i_by_rotation_idx(13,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x3555555555555555555555555555555571e57f7cb2a68cb89f906e9b7fffffff,get_eval_i_by_rotation_idx(14,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2000000000000000000000000000000011234c7e04ca546ec623759080000003,mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),get_eval_i_by_rotation_idx(14,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f21600000000,mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),get_eval_i_by_rotation_idx(14,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1,get_eval_i_by_rotation_idx(4,0, mload(x1)),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x2),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x2, 0)
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffff01,get_eval_i_by_rotation_idx(3,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),0x80,modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffd96,get_eval_i_by_rotation_idx(7,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1c0,mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),get_eval_i_by_rotation_idx(7,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffab,mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(7,0, mload(x1)),get_eval_i_by_rotation_idx(7,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),0x40,modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90afffffecb,get_eval_i_by_rotation_idx(8,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0xe0,mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),get_eval_i_by_rotation_idx(8,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffffd6,mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(8,0, mload(x1)),get_eval_i_by_rotation_idx(8,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),0x20,modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffff66,get_eval_i_by_rotation_idx(9,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x70,mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),get_eval_i_by_rotation_idx(9,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffeb,mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x1)),get_eval_i_by_rotation_idx(9,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),0x10,modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffb3,get_eval_i_by_rotation_idx(10,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x38,mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),get_eval_i_by_rotation_idx(10,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffff6,mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x1)),get_eval_i_by_rotation_idx(10,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),0x8,modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffffda,get_eval_i_by_rotation_idx(11,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1c,mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),get_eval_i_by_rotation_idx(11,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90afffffffb,mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x1)),get_eval_i_by_rotation_idx(11,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),0x4,modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffed,get_eval_i_by_rotation_idx(12,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0xe,mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),get_eval_i_by_rotation_idx(12,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffffe,mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(12,0, mload(x1)),get_eval_i_by_rotation_idx(12,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),0x2,modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffff7,get_eval_i_by_rotation_idx(13,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x7,mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),get_eval_i_by_rotation_idx(13,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffff,mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(13,0, mload(x1)),get_eval_i_by_rotation_idx(13,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),0x1,modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x3555555555555555555555555555555571e57f7cb2a68cb89f906e9b7ffffffc,get_eval_i_by_rotation_idx(14,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2000000000000000000000000000000011234c7e04ca546ec623759080000004,mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),get_eval_i_by_rotation_idx(14,0, mload(x1)), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f21600000000,mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),mulmod(get_eval_i_by_rotation_idx(14,0, mload(x1)),get_eval_i_by_rotation_idx(14,0, mload(x1)), modulus), modulus),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1,get_eval_i_by_rotation_idx(5,0, mload(x1)),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x2),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x2, 0)
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffff0001,get_eval_i_by_rotation_idx(0,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffc001,get_eval_i_by_rotation_idx(7,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffff001,get_eval_i_by_rotation_idx(8,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffc01,get_eval_i_by_rotation_idx(9,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffff01,get_eval_i_by_rotation_idx(10,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffc1,get_eval_i_by_rotation_idx(11,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffff1,get_eval_i_by_rotation_idx(12,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffd,get_eval_i_by_rotation_idx(13,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,get_eval_i_by_rotation_idx(14,0, mload(x1)),modulus),modulus))
            mstore(x2,addmod(mload(x2),mulmod(0x1,get_eval_i_by_rotation_idx(1,0, mload(x1)),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x2),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(add(gate_params, GATE_EVAL_OFFSET),mulmod(mload(add(gate_params, GATE_EVAL_OFFSET)),get_selector_i(0,mload(add(gate_params, SELECTOR_EVALUATIONS_OFFSET))),modulus))
            gates_evaluation := addmod(gates_evaluation,mload(add(gate_params, GATE_EVAL_OFFSET)),modulus)
        }
    }
}
