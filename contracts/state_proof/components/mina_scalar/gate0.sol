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

import "./gate_argument.sol";

// TODO: name component
library mina_scalar_gate0 {
    uint256 constant MODULUS_OFFSET = 0x0;
    uint256 constant THETA_OFFSET = 0x20;

    uint256 constant CONSTRAINT_EVAL_OFFSET = 0x00;
    uint256 constant GATE_EVAL_OFFSET = 0x20;
    uint256 constant GATES_EVALUATIONS_OFFSET = 0x40;
    uint256 constant THETA_ACC_OFFSET = 0x60;
    uint256 constant WITNESS_EVALUATIONS_OFFSET = 0x80;
    uint256 constant CONSTANT_EVALUATIONS_OFFSET = 0xa0;
    uint256 constant SELECTOR_EVALUATIONS_OFFSET =0xc0;

    // TODO: columns_rotations could be hard-coded
    function evaluate_gate_be(
        types.gate_argument_params memory gate_params,
        mina_scalar_split_gen.local_vars_type memory local_vars
    ) external pure returns (uint256 gates_evaluation, uint256 theta_acc) {
        gates_evaluation = local_vars.gates_evaluation;
        theta_acc = local_vars.theta_acc;
        uint256 terms;
        assembly {
            let modulus := mload(gate_params)
            let theta := mload(add(gate_params, THETA_OFFSET))

            mstore(add(local_vars, GATE_EVAL_OFFSET), 0)

            function get_witness_i_by_rotation_idx(idx, rot_idx, ptr) -> result {
                result := mload(
                    add(
                        add(mload(add(add(mload(add(ptr, WITNESS_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx))), 0x20),
                        mul(0x20, rot_idx)
                    )
                )
            }

            function get_selector_i(idx, ptr) -> result {
                result := mload(add(add(ptr, 0x20), mul(0x20, idx)))
            }


            function get_constant_i(idx, ptr) -> result {
                result := mload(add(add(ptr, 0x20), mul(0x20, idx)))
            }
            
            mstore(add(local_vars, GATE_EVAL_OFFSET), 0)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x6819a58283e528e511db4d81cf70f5a0fed467d47c033af2aa9d2e050aa0e50
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, GATE_EVAL_OFFSET),mulmod(mload(add(local_vars, GATE_EVAL_OFFSET)),get_selector_i(1,mload(add(local_vars, SELECTOR_EVALUATIONS_OFFSET))),modulus))
            gates_evaluation := addmod(gates_evaluation,mload(add(local_vars, GATE_EVAL_OFFSET)),modulus)

            mstore(add(local_vars, GATE_EVAL_OFFSET), 0)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffff01
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffff16
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x140
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffab
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90affffff8b
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0xa0
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffffd6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffffc6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x50
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffeb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffe3
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x28
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffff6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffff2
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x14
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90afffffffb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90afffffff9
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0xa
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffffe
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffffd
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x5
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffff
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3555555555555555555555555555555571e57f7cb2a68cb89f906e9b7fffffff
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2000000000000000000000000000000011234c7e04ca546ec623759080000003
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f21600000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffff01
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x80
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffd96
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1c0
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffab
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90afffffecb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0xe0
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffffd6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x20
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffff66
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x70
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffeb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x10
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffb3
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x38
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffff6
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x8
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215ffffffda
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1c
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90afffffffb
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x4
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffed
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0xe
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffffe
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f215fffffff7
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x7
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1555555555555555555555555555555560c232feaddc3849d96cf90affffffff
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3555555555555555555555555555555571e57f7cb2a68cb89f906e9b7ffffffc
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2000000000000000000000000000000011234c7e04ca546ec623759080000004
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac18465fd5bb87093b2d9f21600000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffff0001
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffc001
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffff001
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffc01
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffff01
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffc1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffff1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffd
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, GATE_EVAL_OFFSET),mulmod(mload(add(local_vars, GATE_EVAL_OFFSET)),get_selector_i(0,mload(add(local_vars, SELECTOR_EVALUATIONS_OFFSET))),modulus))
            gates_evaluation := addmod(gates_evaluation,mload(add(local_vars, GATE_EVAL_OFFSET)),modulus)

            mstore(add(local_vars, GATE_EVAL_OFFSET), 0)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, GATE_EVAL_OFFSET),mulmod(mload(add(local_vars, GATE_EVAL_OFFSET)),get_selector_i(2,mload(add(local_vars, SELECTOR_EVALUATIONS_OFFSET))),modulus))
            gates_evaluation := addmod(gates_evaluation,mload(add(local_vars, GATE_EVAL_OFFSET)),modulus)
        }
    }
}