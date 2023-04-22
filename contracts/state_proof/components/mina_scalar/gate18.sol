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
library mina_scalar_gate18 {
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


            function get_constant_i(idx, ptr) -> result {
                result := mload(add(add(ptr, 0x20), mul(0x20, idx)))
            }
            
            mstore(add(local_vars, GATE_EVAL_OFFSET), 0)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x192958f716b9b37a16389fa1780469fcb2749a74d1f9e4a2b6e662cb7d1bfd94
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1d70822e80b8581cfb5ab2c8822851174db06f98c33edea8c227e30dc22a6b3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0xf24f954496903346d4d753deb0b76c2e26e4dbebf04906842d108dc883cda01
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x28beef43e4fa739fe900a17ead54c004b4182caf07ae3e235c20915be480a9c7
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x3a6b0330e79c66c4bc52f5ec3a0385ac2ca71b99db19887049ede3fcc59619d4
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2d2c9057cafceb967f3fa5e2b7432af2f3a9556b26410784eb48b2a2d4b514f5
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x154e83714c9641589160f3c7a17450390d0fda1f7b8dd86db5ead4b016b263ac
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3f336eacd7e9a3ec67950ed81ef7461a48a08c9e40666a67558e2746a4b57aca
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x3871b3a7749222f01812ac560da4953c5f5bd735c9e5dc5efad79ddb66fae6c1
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3b26592d8f96997714bcb9eac4c7f39ee808ce0b0e3a8a5a0c0650405ebc2ce6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3d57fa111cce837451e082ea541b2d8033e6ed2c6f61740c012db87dc88b3cdd
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x264f6d16392002e14e4920d243ff44dd9e8cf174e256dd2ff0b96153afd48444
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x30bb15c1eb3c1b7b61185ada0188e8f49bedf286d313c673c249ce0e6cd50964
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1d70822e80b8581cfb5ab2c8822851174db06f98c33edea8c227e30dc22a6b3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0xf24f954496903346d4d753deb0b76c2e26e4dbebf04906842d108dc883cda01
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x28beef43e4fa739fe900a17ead54c004b4182caf07ae3e235c20915be480a9c7
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x117a98436171c9642088b7293809887ca5e684a6352f8eae7c1b5621e06aec88
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2d2c9057cafceb967f3fa5e2b7432af2f3a9556b26410784eb48b2a2d4b514f5
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x154e83714c9641589160f3c7a17450390d0fda1f7b8dd86db5ead4b016b263ac
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3f336eacd7e9a3ec67950ed81ef7461a48a08c9e40666a67558e2746a4b57aca
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x83ca4fa9e8e67d33828b19f7e0353d0abf77918faab23025bdcc870682ae453
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3b26592d8f96997714bcb9eac4c7f39ee808ce0b0e3a8a5a0c0650405ebc2ce6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3d57fa111cce837451e082ea541b2d8033e6ed2c6f61740c012db87dc88b3cdd
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x264f6d16392002e14e4920d243ff44dd9e8cf174e256dd2ff0b96153afd48444
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x16243002a4aa298e37a35bdfc853a19b4f5756299949b4636bbf6ce6a1a0e264
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1d70822e80b8581cfb5ab2c8822851174db06f98c33edea8c227e30dc22a6b3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0xf24f954496903346d4d753deb0b76c2e26e4dbebf04906842d108dc883cda01
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x28beef43e4fa739fe900a17ead54c004b4182caf07ae3e235c20915be480a9c7
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x1fef67bdd1fab3e2233b9abee2ffd2d45c9e741a419fb5feb302aee942fb5ae1
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2d2c9057cafceb967f3fa5e2b7432af2f3a9556b26410784eb48b2a2d4b514f5
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x154e83714c9641589160f3c7a17450390d0fda1f7b8dd86db5ead4b016b263ac
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3f336eacd7e9a3ec67950ed81ef7461a48a08c9e40666a67558e2746a4b57aca
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x3821cd12b3aebcbcf10bc510eff06b7129ecedc475ea56798aeff53926d3237d
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3b26592d8f96997714bcb9eac4c7f39ee808ce0b0e3a8a5a0c0650405ebc2ce6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3d57fa111cce837451e082ea541b2d8033e6ed2c6f61740c012db87dc88b3cdd
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x264f6d16392002e14e4920d243ff44dd9e8cf174e256dd2ff0b96153afd48444
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0xb16a5233f3a3cb02c7546db95fb33eff8502041b5d3b1e0644e6ad06b1c9e68
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1d70822e80b8581cfb5ab2c8822851174db06f98c33edea8c227e30dc22a6b3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0xf24f954496903346d4d753deb0b76c2e26e4dbebf04906842d108dc883cda01
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x28beef43e4fa739fe900a17ead54c004b4182caf07ae3e235c20915be480a9c7
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x22a050ea8ed93a66dcd67dca935f1584a06e233bec107d80baad60c4b8f059de
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2d2c9057cafceb967f3fa5e2b7432af2f3a9556b26410784eb48b2a2d4b514f5
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x154e83714c9641589160f3c7a17450390d0fda1f7b8dd86db5ead4b016b263ac
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3f336eacd7e9a3ec67950ed81ef7461a48a08c9e40666a67558e2746a4b57aca
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x29f57fe8942d7e1c05647d1bbf9c338429d7e0e871af8a9b8dffa53e83a81e2f
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3b26592d8f96997714bcb9eac4c7f39ee808ce0b0e3a8a5a0c0650405ebc2ce6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3d57fa111cce837451e082ea541b2d8033e6ed2c6f61740c012db87dc88b3cdd
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x264f6d16392002e14e4920d243ff44dd9e8cf174e256dd2ff0b96153afd48444
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x2813380a214eb73abd5dd2fd4f67bc68fdb58ec04c4ba59affb724a00ce4dbfb
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1d70822e80b8581cfb5ab2c8822851174db06f98c33edea8c227e30dc22a6b3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0xf24f954496903346d4d753deb0b76c2e26e4dbebf04906842d108dc883cda01
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x28beef43e4fa739fe900a17ead54c004b4182caf07ae3e235c20915be480a9c7
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,1, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x3fdf59551e807dd438fca25c476ce7695a2546c79a6a65323e46c1450fefe4c4
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2d2c9057cafceb967f3fa5e2b7432af2f3a9556b26410784eb48b2a2d4b514f5
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x154e83714c9641589160f3c7a17450390d0fda1f7b8dd86db5ead4b016b263ac
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3f336eacd7e9a3ec67950ed81ef7461a48a08c9e40666a67558e2746a4b57aca
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,2, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x3615f13ef3f18846c7a5a7332a133c3796eaaba35a2202051092a43fb058372b
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3b26592d8f96997714bcb9eac4c7f39ee808ce0b0e3a8a5a0c0650405ebc2ce6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3d57fa111cce837451e082ea541b2d8033e6ed2c6f61740c012db87dc88b3cdd
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x264f6d16392002e14e4920d243ff44dd9e8cf174e256dd2ff0b96153afd48444
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,1, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, GATE_EVAL_OFFSET),mulmod(mload(add(local_vars, GATE_EVAL_OFFSET)),get_selector_i(18,mload(add(local_vars, SELECTOR_EVALUATIONS_OFFSET))),modulus))
            gates_evaluation := addmod(gates_evaluation,mload(add(local_vars, GATE_EVAL_OFFSET)),modulus)            



                        mstore(add(local_vars, GATE_EVAL_OFFSET), 0)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x10000000000000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x100000000000000000000000000000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1000000000000000000000000000000000000000000000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd188dd64200000002
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x10000000000000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dcae8d841d0994a8df
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x10000000000000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dc8c46eb2100000002
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x10000000000000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dccc46eb2100000002
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, GATE_EVAL_OFFSET),mulmod(mload(add(local_vars, GATE_EVAL_OFFSET)),get_selector_i(19,mload(add(local_vars, SELECTOR_EVALUATIONS_OFFSET))),modulus))
            gates_evaluation := addmod(gates_evaluation,mload(add(local_vars, GATE_EVAL_OFFSET)),modulus)




                        
            mstore(add(local_vars, GATE_EVAL_OFFSET), 0)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffb
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x2
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x3
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x6
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20ffffffff
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb20fffffffe
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x4000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x400000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(3,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x100000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(4,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(5,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x10000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(6,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x4000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(7,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(8,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x400
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(9,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x100
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(10,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(11,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x10
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(12,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x4
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(13,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(14,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x10000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,2, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, GATE_EVAL_OFFSET),mulmod(mload(add(local_vars, GATE_EVAL_OFFSET)),get_selector_i(20,mload(add(local_vars, SELECTOR_EVALUATIONS_OFFSET))),modulus))
            gates_evaluation := addmod(gates_evaluation,mload(add(local_vars, GATE_EVAL_OFFSET)),modulus)



            mstore(add(local_vars, GATE_EVAL_OFFSET), 0)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
            terms:=0x10000000000000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(1,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x1
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(0,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            terms:=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
            terms:=mulmod(terms, get_eval_i_by_rotation_idx(2,0, mload(add(local_vars, WITNESS_EVALUATIONS_OFFSET))), modulus)
            mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
            mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
            theta_acc := mulmod(theta_acc,theta,modulus)
            mstore(add(local_vars, GATE_EVAL_OFFSET),mulmod(mload(add(local_vars, GATE_EVAL_OFFSET)),get_selector_i(21,mload(add(local_vars, SELECTOR_EVALUATIONS_OFFSET))),modulus))
            gates_evaluation := addmod(gates_evaluation,mload(add(local_vars, GATE_EVAL_OFFSET)),modulus)
        }
    }
}
