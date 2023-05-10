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

import "@nilfoundation/evm-placeholder-verification/contracts/types.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/logging.sol";

// TODO: name component
library mina_scalar_gate22 {
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
        types.gate_argument_params memory gate_params
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
            mstore(add(gate_params, GATE_EVAL_OFFSET), 0)
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,get_eval_i_by_rotation_idx(0,1, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x1,get_eval_i_by_rotation_idx(0,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,get_eval_i_by_rotation_idx(13,1, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x1,get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(13,1, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,1, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,1, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,1, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,1, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),get_eval_i_by_rotation_idx(1,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))), modulus), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x1,get_eval_i_by_rotation_idx(1,2, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,get_eval_i_by_rotation_idx(2,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(1,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(0,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),get_eval_i_by_rotation_idx(4,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(1,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),get_eval_i_by_rotation_idx(3,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))), modulus),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(1,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(0,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),get_eval_i_by_rotation_idx(6,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(1,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),get_eval_i_by_rotation_idx(5,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(1,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(0,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),get_eval_i_by_rotation_idx(8,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(1,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),get_eval_i_by_rotation_idx(7,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(1,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(0,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),get_eval_i_by_rotation_idx(10,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))), modulus), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(1,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),get_eval_i_by_rotation_idx(9,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(1,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(0,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),get_eval_i_by_rotation_idx(12,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))), modulus), modulus), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000,mulmod(get_eval_i_by_rotation_idx(1,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),mulmod(get_eval_i_by_rotation_idx(13,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),get_eval_i_by_rotation_idx(11,0, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))), modulus), modulus), modulus), modulus), modulus),modulus),modulus))
            mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),mulmod(0x1,get_eval_i_by_rotation_idx(2,1, mload(add(gate_params, WITNESS_EVALUATIONS_OFFSET))),modulus),modulus))
            mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
            mstore(add(gate_params, GATE_EVAL_OFFSET),mulmod(mload(add(gate_params, GATE_EVAL_OFFSET)),get_selector_i(22,mload(add(gate_params, SELECTOR_EVALUATIONS_OFFSET))),modulus))
            gates_evaluation := addmod(gates_evaluation,mload(add(gate_params, GATE_EVAL_OFFSET)),modulus)
        }
    }
}