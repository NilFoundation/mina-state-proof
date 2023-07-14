
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

library account_gate11{
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

			//Gate11
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
			terms:=0x710c54a49e3ee85cb9a5fe8563745b3ffd03f47e96de4c99257678c0b622ba6
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
			terms:=0x66d07c0d9ebc24242cca9fb5e5eb250febbb4bfe4b57525042e8196f5551df2
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
			terms:=0xafd78688148e37e4ef132fc655266307859145bc64b2deb128f132505e239c9
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
			terms:=0x504a43ed9fdfa79233345cd22fab3267e52e0c73eb680451900e83b25682914
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
			terms:=0x28d483d27181b4f92e7c5da8a486f8b651af8ca772e8f12109d429c08d621990
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
			terms:=0x114ac01c5d8797758fb6ba961ab5f0f2fbad634d4284615ca459c82b0982a81d
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
			terms:=0x3c8a51a94726cef2aac12882bf92123c320d5aa1d7318750aac2d535f874afcc
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
			terms:=0x22b65f2ac43d66c340e04a2e256448903ddc28ca336724dbeb6ddc30e83e10c9
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
			terms:=0x2cd2e8478354928f82205e0fe20e8db54ecd41127f88a9fba2190ab6806acea1
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
			terms:=0x39d25ad7f6b727393b5338195e55bde112a7d782650bb2a698cc72a1198aa07c
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
			terms:=0x35b4b2a321ab568b15b1a811becd2d54fd35d5fb1733c844dd6e0fcfe5227f08
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
			terms:=0xca90e04153b6c33548ad48f44127de33dad333a76c82170cbb434f90079b170
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
			terms:=0x3bd8de175633cdaa87ae014f1fe6f3a22651cde07a05259d1ac7f2260075bfa8
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
			terms:=0x3ac264d9cc000ce35b03a8db3194bbddf0c5702e193461487744c1a53208b750
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
			terms:=0x1982693515021a242c24e0f9974f6332cf1c760be8f864aa2eb4ced304b37fe5
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, GATE_EVAL_OFFSET),mulmod(mload(add(local_vars, GATE_EVAL_OFFSET)),get_selector_i(11,local_vars),modulus))
			gates_evaluation := addmod(gates_evaluation,mload(add(local_vars, GATE_EVAL_OFFSET)),modulus)

        }
    }
}
