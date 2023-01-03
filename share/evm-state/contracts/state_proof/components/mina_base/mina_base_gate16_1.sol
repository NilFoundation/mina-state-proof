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

// TODO: name component
library mina_base_gate16_1 {
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
//            mstore(add(gate_params, GATE_EVAL_OFFSET), 0)

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
            let x1 := add(gate_params, CONSTRAINT_EVAL_OFFSET)
            let x2 := add(gate_params, WITNESS_EVALUATIONS_OFFSET)
            mstore(x1, 0)
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(10,2, mload(x2)),get_eval_i_by_rotation_idx(9,2, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(10,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x2)),get_eval_i_by_rotation_idx(9,0, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(10,2, mload(x2)),get_eval_i_by_rotation_idx(0,2, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(12,1, mload(x2)),get_eval_i_by_rotation_idx(9,2, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(12,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x2)),get_eval_i_by_rotation_idx(9,0, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(12,1, mload(x2)),get_eval_i_by_rotation_idx(0,2, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),get_eval_i_by_rotation_idx(10,2, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecffffffff,mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(9,2, mload(x2)),get_eval_i_by_rotation_idx(9,0, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x2)),get_eval_i_by_rotation_idx(9,0, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(0,2, mload(x2)),get_eval_i_by_rotation_idx(9,0, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecffffffff,mulmod(get_eval_i_by_rotation_idx(9,2, mload(x2)),get_eval_i_by_rotation_idx(10,2, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(9,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(9,2, mload(x2)),get_eval_i_by_rotation_idx(9,0, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(9,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(9,0, mload(x2)),get_eval_i_by_rotation_idx(9,0, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(9,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(0,2, mload(x2)),get_eval_i_by_rotation_idx(9,0, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x1),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x1, 0)
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(12,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(12,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(12,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(0,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(14,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(14,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(14,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(0,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(12,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecffffffff,mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(0,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecffffffff,mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(12,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(11,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(0,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(10,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x1),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x1, 0)
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(14,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(14,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(14,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(0,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(1,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(1,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(1,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(0,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(0,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(14,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecffffffff,mulmod(get_eval_i_by_rotation_idx(0,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(0,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(0,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(0,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecffffffff,mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(14,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x2,mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(13,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(0,2, mload(x2)),mulmod(get_eval_i_by_rotation_idx(11,0, mload(x2)),mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),get_eval_i_by_rotation_idx(2,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x1),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x1, 0)
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecffffffe1,get_eval_i_by_rotation_idx(4,2, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecfffffff1,get_eval_i_by_rotation_idx(2,0, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecfffffff9,get_eval_i_by_rotation_idx(3,0, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecfffffffd,get_eval_i_by_rotation_idx(4,0, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ecffffffff,get_eval_i_by_rotation_idx(5,0, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,get_eval_i_by_rotation_idx(6,0, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,get_eval_i_by_rotation_idx(5,2, mload(x2)),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x1),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x1, 0)
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(2,1, mload(x2)),get_eval_i_by_rotation_idx(8,1, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,get_eval_i_by_rotation_idx(8,1, mload(x2)),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x1),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x1, 0)
            mstore(x1,addmod(mload(x1),0x224698fc0994a8dd8c46eb2100000000,modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,get_eval_i_by_rotation_idx(5,1, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x496d41af7ccfdaa97fae231004ccf58c412ebcb86019a410000000000000000,get_eval_i_by_rotation_idx(3,1, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3fffffffffffffffffffffffffffffffffffffffffb8503e0ce645cc00000001,mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(5,1, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3fffffffffffffffffffffffffffffffffffffffffb8503e0ce645cc00000001,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),get_eval_i_by_rotation_idx(3,1, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(5,1, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x1),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x1, 0)
            mstore(x1,addmod(mload(x1),0x224698fc0994a8dd8c46eb2100000001,modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,get_eval_i_by_rotation_idx(5,1, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x496d41af7ccfdaa97fae231004ccf5908a01dc3992aebfc188dd64200000001,get_eval_i_by_rotation_idx(4,1, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3fffffffffffffffffffffffffffffffffffffffffb8503e0ce645cc00000000,mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(5,1, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3fffffffffffffffffffffffffffffffffffffffffb8503e0ce645cc00000000,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),get_eval_i_by_rotation_idx(4,1, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(5,1, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x1),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x1, 0)
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(2,1, mload(x2)),get_eval_i_by_rotation_idx(0,0, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x496d41af7ccfdaa97fae231004ccf58c412ebcb86019a410000000000000000,mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3fffffffffffffffffffffffffffffffffffffffffb8503e0ce645cc00000001,mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3b692be50833025568051dceffb330a73bed143479b6b5fd0ce645cc00000001,mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3fffffffffffffffffffffffffffffffffffffffffb8503e0ce645cc00000001,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x224698fc0994a8dd8c46eb2100000001,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3b692be50833025568051dceffb330a73bed143479b6b5fd0ce645cc00000001,mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x224698fc0994a8dd8c46eb2100000001,mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x496d41af7ccfdaa97fae231004ccf5908a01dc3992aebfc188dd64200000001,mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3fffffffffffffffffffffffffffffffffffffffffb8503e0ce645cc00000000,mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3fffffffffffffffffffffffffffffffffffffffffb8503e0ce645cc00000000,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(6,1, mload(x2)), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,get_eval_i_by_rotation_idx(0,1, mload(x2)),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x1),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x1, 0)
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(8,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(2,1, mload(x2)),get_eval_i_by_rotation_idx(1,0, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3fffffffffffffffffffffffffffffffffffffffffb8503e0ce645cc00000001,mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(7,1, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(3,1, mload(x2)),get_eval_i_by_rotation_idx(7,1, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x224698fc0994a8dd8c46eb2100000001,mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(7,1, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(4,1, mload(x2)),get_eval_i_by_rotation_idx(7,1, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,get_eval_i_by_rotation_idx(1,1, mload(x2)),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x1),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(x1, 0)
            mstore(x1,addmod(mload(x1),0x2a1a93d689e9f8b44bf04c0fd60a0f9af9d508bd2e179c458fd2678ffbb69a75,modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3b692be5082e35c713e4bee4711f3ce0b48cd2bd5745ac11d309bb5c80000001,get_eval_i_by_rotation_idx(5,1, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x3b692be50833025568051dceffb330a73bed143479b6b5fd0ce645cc00000001,get_eval_i_by_rotation_idx(5,1, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),get_eval_i_by_rotation_idx(5,1, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1b692be5082e35c713e4bee4711f3ce08122ed4348e6aec5809f5aab00000000,get_eval_i_by_rotation_idx(5,1, mload(x2)),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x200000000000000000000000000000003369e57a0e5efd4c526a60b180000001,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),get_eval_i_by_rotation_idx(5,1, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x224698fc0994a8dd8c46eb2100000001,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),get_eval_i_by_rotation_idx(5,1, mload(x2)), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000,mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),mulmod(get_eval_i_by_rotation_idx(5,1, mload(x2)),get_eval_i_by_rotation_idx(5,1, mload(x2)), modulus), modulus),modulus),modulus))
            mstore(x1,addmod(mload(x1),mulmod(0x1,get_eval_i_by_rotation_idx(8,1, mload(x2)),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(x1),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(add(gate_params, GATE_EVAL_OFFSET),mulmod(mload(add(gate_params, GATE_EVAL_OFFSET)),get_selector_i(16,mload(add(gate_params, SELECTOR_EVALUATIONS_OFFSET))),modulus))
            gates_evaluation := addmod(gates_evaluation,mload(add(gate_params, GATE_EVAL_OFFSET)),modulus)

        }
    }
}
