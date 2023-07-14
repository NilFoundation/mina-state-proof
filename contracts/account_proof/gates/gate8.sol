
// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

library account_gate8{
    uint256 constant MODULUS_OFFSET = 0x0;
    uint256 constant THETA_OFFSET = 0x20;

    uint256 constant CONSTRAINT_EVAL_OFFSET = 0x00;
    uint256 constant GATE_EVAL_OFFSET = 0x20;
    uint256 constant GATES_EVALUATIONS_OFFSET = 0x40;
    uint256 constant THETA_ACC_OFFSET = 0x60;
    
	uint256 constant WITNESS_EVALUATIONS_OFFSET = 0x80;
	uint256 constant SELECTOR_EVALUATIONS_OFFSET = 0xa0;


    function evaluate_gate_be(
        types.gate_argument_params memory gate_params,
        account_gate_argument_split_gen.local_vars_type memory local_vars
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
                result := mload(add(add(mload(add(ptr, SELECTOR_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }

			//Gate8
			mstore(add(local_vars, GATE_EVAL_OFFSET), 0)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(3,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x25642daf8a81d610b6a646410a64b19f403c42cb8be86733e1431140986386fe
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x7b55f6050c5b78c81d29b095fcf55dbf3d93bb6ae6857e50278a679df3af934
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2d484fdf643cf7ff9b2a31b585fc9ac2a1233f549a628a5931b192e6193012c
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2a86e064415dec6c8df737d86b1499810cc798bfa396ae72191de52e1b15aee8
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(4,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x3611a838f43caeddf4ef867c503054417aae305760a767dd747585f94b40c5bf
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1f67666943d65692e897b2c52b37a67ef131727cd42a9b9d7a92d598c95dba72
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2b1c6524d1e8e51dcdee9be61180d9270927bb1363e9d68364b055783c4d1964
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x252414a163b2aea1302daf1411a95d580b5b5abe407724dad781ee674caf419d
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(5,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x28babbca8497809a56a6f3e209de7e74cdf3c327c7f37e8763ae1fc9e9109836
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(0,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x356d9c23e5e62e83040ea4fe9944da08c669ca8e81f47139c3efafcd3d3beca
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(1,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x30e04108a2b549c4857ed07f484fc8c6f6a77299f927ccf4bc7af17f551eeb5
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(2,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2040b8c77bb565db6513dac171bd9f1b773cb6901f234e1b786e226bc311343e
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(6,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x25642daf8a81d610b6a646410a64b19f403c42cb8be86733e1431140986386fe
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x7b55f6050c5b78c81d29b095fcf55dbf3d93bb6ae6857e50278a679df3af934
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2d484fdf643cf7ff9b2a31b585fc9ac2a1233f549a628a5931b192e6193012c
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0xbe756d6aa913ae5f79ba644619c57de4e3f606f3ac9647ffe394d3cbcb150f3
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(7,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x3611a838f43caeddf4ef867c503054417aae305760a767dd747585f94b40c5bf
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1f67666943d65692e897b2c52b37a67ef131727cd42a9b9d7a92d598c95dba72
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2b1c6524d1e8e51dcdee9be61180d9270927bb1363e9d68364b055783c4d1964
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x36bf94a3c50fd6f0668bfa2f3ae4196add96e6bb34be0e6a25c056e8cd170063
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(8,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x28babbca8497809a56a6f3e209de7e74cdf3c327c7f37e8763ae1fc9e9109836
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(3,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x356d9c23e5e62e83040ea4fe9944da08c669ca8e81f47139c3efafcd3d3beca
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(4,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x30e04108a2b549c4857ed07f484fc8c6f6a77299f927ccf4bc7af17f551eeb5
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(5,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1c131a28f4c733362bc326dc1a1c1d09f52911bf780b0a19a091c30bcc90a43a
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(9,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x25642daf8a81d610b6a646410a64b19f403c42cb8be86733e1431140986386fe
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x7b55f6050c5b78c81d29b095fcf55dbf3d93bb6ae6857e50278a679df3af934
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2d484fdf643cf7ff9b2a31b585fc9ac2a1233f549a628a5931b192e6193012c
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x27ad2a8b1b92c8f5f4e19b093be11472e1770236e4a6cfb6330e01f48198dcb4
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(10,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x3611a838f43caeddf4ef867c503054417aae305760a767dd747585f94b40c5bf
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1f67666943d65692e897b2c52b37a67ef131727cd42a9b9d7a92d598c95dba72
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2b1c6524d1e8e51dcdee9be61180d9270927bb1363e9d68364b055783c4d1964
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x359a8fd833172b0dc715769221d8c48aea919094bf168cb4e5b49354d74f3171
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(11,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x28babbca8497809a56a6f3e209de7e74cdf3c327c7f37e8763ae1fc9e9109836
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(6,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x356d9c23e5e62e83040ea4fe9944da08c669ca8e81f47139c3efafcd3d3beca
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(7,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x30e04108a2b549c4857ed07f484fc8c6f6a77299f927ccf4bc7af17f551eeb5
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(8,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0xb7d0675b913ca7ef7044497026b070d679f5c89cd9dd7896ea822a7aee0a5d4
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(12,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x25642daf8a81d610b6a646410a64b19f403c42cb8be86733e1431140986386fe
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x7b55f6050c5b78c81d29b095fcf55dbf3d93bb6ae6857e50278a679df3af934
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2d484fdf643cf7ff9b2a31b585fc9ac2a1233f549a628a5931b192e6193012c
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x9d0e9b0736fa4cca5934089ece2dbd200eb78132a131ae6eca072b13ab9c13
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(13,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x3611a838f43caeddf4ef867c503054417aae305760a767dd747585f94b40c5bf
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1f67666943d65692e897b2c52b37a67ef131727cd42a9b9d7a92d598c95dba72
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2b1c6524d1e8e51dcdee9be61180d9270927bb1363e9d68364b055783c4d1964
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x381c680afc063e315fd7b9a4d6af15bbd730d31153e52374fa8a9e967a96b211
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(14,0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x28babbca8497809a56a6f3e209de7e74cdf3c327c7f37e8763ae1fc9e9109836
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(9,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x356d9c23e5e62e83040ea4fe9944da08c669ca8e81f47139c3efafcd3d3beca
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(10,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x30e04108a2b549c4857ed07f484fc8c6f6a77299f927ccf4bc7af17f551eeb5
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(11,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x3bfa0e038ee78dc8c2914af5f60404fa6fd65e1b68980b632e3f7ed624e8578b
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(0,1, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x25642daf8a81d610b6a646410a64b19f403c42cb8be86733e1431140986386fe
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x7b55f6050c5b78c81d29b095fcf55dbf3d93bb6ae6857e50278a679df3af934
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2d484fdf643cf7ff9b2a31b585fc9ac2a1233f549a628a5931b192e6193012c
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x341f7b714c1f638fd8eef527bd3afdbc05aee95abec8b5149c2e69985da9a740
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(1,1, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x3611a838f43caeddf4ef867c503054417aae305760a767dd747585f94b40c5bf
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x1f67666943d65692e897b2c52b37a67ef131727cd42a9b9d7a92d598c95dba72
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x2b1c6524d1e8e51dcdee9be61180d9270927bb1363e9d68364b055783c4d1964
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x19487877026753fdf4536d2f1886d44a225992457174b1257b94e15ca2645791
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=get_witness_i_by_rotation_idx(2,1, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x28babbca8497809a56a6f3e209de7e74cdf3c327c7f37e8763ae1fc9e9109836
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(12,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x356d9c23e5e62e83040ea4fe9944da08c669ca8e81f47139c3efafcd3d3beca
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(13,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x30e04108a2b549c4857ed07f484fc8c6f6a77299f927ccf4bc7af17f551eeb5
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			terms:=mulmod(terms, get_witness_i_by_rotation_idx(14,0, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=0x702ace72c6faa37d0106422cccea5ac0637d4c5cae038b32927a9d9aa205a8e
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, GATE_EVAL_OFFSET),mulmod(mload(add(local_vars, GATE_EVAL_OFFSET)),get_selector_i(8,local_vars),modulus))
			gates_evaluation := addmod(gates_evaluation,mload(add(local_vars, GATE_EVAL_OFFSET)),modulus)

        }
    }
}
