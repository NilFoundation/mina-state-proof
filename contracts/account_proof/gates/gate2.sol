
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

import "../contracts/types.sol";
import "../contracts/logging.sol";

// TODO: name component
library gate2{
    uint256 constant MODULUS_OFFSET = 0x0;
    uint256 constant THETA_OFFSET = 0x20;
    uint256 constant CONSTRAINT_EVAL_OFFSET = 0x40;
    uint256 constant GATE_EVAL_OFFSET = 0x60;
    uint256 constant GATES_EVALUATIONS_OFFSET = 0x80;
    uint256 constant THETA_ACC_OFFSET = 0xa0;
    uint256 constant WITNESS_EVALUATIONS_OFFSET = 0xc0;
    uint256 constant CONSTANT_EVALUATIONS_OFFSET = 0xe0;
    uint256 constant SELECTOR_EVALUATIONS_OFFSET =0x100;
    uint256 constant PUBLIC_INPUT_EVALUATIONS_OFFSET =0x120;

    function evaluate_gate_be(
        types.gate_argument_local_vars memory gate_params
    ) external pure returns (uint256 gates_evaluation, uint256 theta_acc) {
        gates_evaluation = gate_params.gates_evaluation;
        theta_acc = gate_params.theta_acc;
        uint256 terms;
        assembly {
            let modulus := mload(gate_params)
            mstore(add(gate_params, GATE_EVAL_OFFSET), 0)

            function get_witness_i_by_rotation_idx(idx, rot_idx, ptr) -> result {
                result := mload(
                    add(
                        add(mload(add(add(mload(add(ptr, WITNESS_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx))), 0x20),
                        mul(0x20, rot_idx)
                    )
                )
            }

            function get_selector_i(idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, SELECTOR_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }

            function get_public_input_i(idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, PUBLIC_INPUT_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }

            // rot_idx is temporary unused
            function get_constant_i_by_rotation_idx(idx, rot_idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, CONSTANT_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }

			//Gate2
			mstore(add(gate_params, GATE_EVAL_OFFSET), 0)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0xb57260badff5653d7fde8ed417e16fa8bcaeca3ff415a361d690dcda1346c97
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x25642daf8a81d610b6a646410a64b19f403c42cb8be86733e1431140986386fe
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x7b55f6050c5b78c81d29b095fcf55dbf3d93bb6ae6857e50278a679df3af934
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2d484fdf643cf7ff9b2a31b585fc9ac2a1233f549a628a5931b192e6193012c
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x3686aa934c12341b0cc122df6b0ebbc4d6f7d237b19cb6c014c94964465d2327
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x3611a838f43caeddf4ef867c503054417aae305760a767dd747585f94b40c5bf
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1f67666943d65692e897b2c52b37a67ef131727cd42a9b9d7a92d598c95dba72
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2b1c6524d1e8e51dcdee9be61180d9270927bb1363e9d68364b055783c4d1964
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x15b2fd73f652c63cf9994874ba30522afaa736c2d1b0908126adce8686d8d9ad
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x28babbca8497809a56a6f3e209de7e74cdf3c327c7f37e8763ae1fc9e9109836
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x356d9c23e5e62e83040ea4fe9944da08c669ca8e81f47139c3efafcd3d3beca
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x30e04108a2b549c4857ed07f484fc8c6f6a77299f927ccf4bc7af17f551eeb5
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x33ce497097af4c428e01b17667b1d378e0f17500b45aaa52eabbede98feab4ce
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x25642daf8a81d610b6a646410a64b19f403c42cb8be86733e1431140986386fe
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x7b55f6050c5b78c81d29b095fcf55dbf3d93bb6ae6857e50278a679df3af934
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2d484fdf643cf7ff9b2a31b585fc9ac2a1233f549a628a5931b192e6193012c
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x25d835f46ac2c2459471fe30f828939f08257be86a1ef9c0d90943c8ab0d1271
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x3611a838f43caeddf4ef867c503054417aae305760a767dd747585f94b40c5bf
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1f67666943d65692e897b2c52b37a67ef131727cd42a9b9d7a92d598c95dba72
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2b1c6524d1e8e51dcdee9be61180d9270927bb1363e9d68364b055783c4d1964
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x2f651683da29fdbd47928e96e692dded2fdddfa929739ee2619bc553facfce81
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x28babbca8497809a56a6f3e209de7e74cdf3c327c7f37e8763ae1fc9e9109836
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x356d9c23e5e62e83040ea4fe9944da08c669ca8e81f47139c3efafcd3d3beca
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x30e04108a2b549c4857ed07f484fc8c6f6a77299f927ccf4bc7af17f551eeb5
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x96736cd0d5e9084465453f7613d218658b0407a98c480b35c7ddd2257c5263d
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x25642daf8a81d610b6a646410a64b19f403c42cb8be86733e1431140986386fe
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x7b55f6050c5b78c81d29b095fcf55dbf3d93bb6ae6857e50278a679df3af934
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2d484fdf643cf7ff9b2a31b585fc9ac2a1233f549a628a5931b192e6193012c
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x381da1f537045c23ec9f07565605f4214437c6f92a3c483e16268ffcd521941
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x3611a838f43caeddf4ef867c503054417aae305760a767dd747585f94b40c5bf
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1f67666943d65692e897b2c52b37a67ef131727cd42a9b9d7a92d598c95dba72
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2b1c6524d1e8e51dcdee9be61180d9270927bb1363e9d68364b055783c4d1964
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x103afdc3a1b512a5582035f0ab6d0e49329b6862d33e2fbb75b81df8737a7588
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x28babbca8497809a56a6f3e209de7e74cdf3c327c7f37e8763ae1fc9e9109836
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x356d9c23e5e62e83040ea4fe9944da08c669ca8e81f47139c3efafcd3d3beca
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x30e04108a2b549c4857ed07f484fc8c6f6a77299f927ccf4bc7af17f551eeb5
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x13edb8ca0c06dbab904b0205d5fe71fc2d163528666479491372a3888125989c
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x25642daf8a81d610b6a646410a64b19f403c42cb8be86733e1431140986386fe
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x7b55f6050c5b78c81d29b095fcf55dbf3d93bb6ae6857e50278a679df3af934
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2d484fdf643cf7ff9b2a31b585fc9ac2a1233f549a628a5931b192e6193012c
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x2d378a36486a6e5306fcc07493e1ca8efb824dd81604895cb853adac5cc7ddb0
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x3611a838f43caeddf4ef867c503054417aae305760a767dd747585f94b40c5bf
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1f67666943d65692e897b2c52b37a67ef131727cd42a9b9d7a92d598c95dba72
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2b1c6524d1e8e51dcdee9be61180d9270927bb1363e9d68364b055783c4d1964
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x3256ca176a7a82c658247b895125a5b0f29e79665f9f1dbc548bcef77aaad74
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x28babbca8497809a56a6f3e209de7e74cdf3c327c7f37e8763ae1fc9e9109836
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x356d9c23e5e62e83040ea4fe9944da08c669ca8e81f47139c3efafcd3d3beca
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x30e04108a2b549c4857ed07f484fc8c6f6a77299f927ccf4bc7af17f551eeb5
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x1e7148a905a0e2060e146dd107f4f7adc9bf1f54d2bebc1a8b3e1bda7ea278a8
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x25642daf8a81d610b6a646410a64b19f403c42cb8be86733e1431140986386fe
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x7b55f6050c5b78c81d29b095fcf55dbf3d93bb6ae6857e50278a679df3af934
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2d484fdf643cf7ff9b2a31b585fc9ac2a1233f549a628a5931b192e6193012c
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,1, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x1c430efcd6a8fea10e8e044bcd6435f3ca710076b71dd326e8aa8d1dcfe3043b
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x3611a838f43caeddf4ef867c503054417aae305760a767dd747585f94b40c5bf
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1f67666943d65692e897b2c52b37a67ef131727cd42a9b9d7a92d598c95dba72
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2b1c6524d1e8e51dcdee9be61180d9270927bb1363e9d68364b055783c4d1964
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,1, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x28b8b3c495643efa8209b461b29d45245a531280cb75a1547d0dcb8afa284316
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x28babbca8497809a56a6f3e209de7e74cdf3c327c7f37e8763ae1fc9e9109836
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x356d9c23e5e62e83040ea4fe9944da08c669ca8e81f47139c3efafcd3d3beca
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x30e04108a2b549c4857ed07f484fc8c6f6a77299f927ccf4bc7af17f551eeb5
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,1, gate_params), modulus)
			mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(gate_params, GATE_EVAL_OFFSET),addmod(mload(add(gate_params, GATE_EVAL_OFFSET)),mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)
			mstore(add(gate_params, GATE_EVAL_OFFSET),mulmod(mload(add(gate_params, GATE_EVAL_OFFSET)),get_selector_i(2,gate_params),modulus))
			gates_evaluation := addmod(gates_evaluation,mload(add(gate_params, GATE_EVAL_OFFSET)),modulus)

        }
    }
}
