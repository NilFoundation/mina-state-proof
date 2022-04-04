// SPDX-License-Identifier: MIT OR Apache-2.0
//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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
pragma experimental ABIEncoderV2;

import "truffle/Assert.sol";
import '../contracts/types.sol';
import '../contracts/components/unified_addition.sol';

contract TestUnifiedAddition {
    function test_unified_addition_case1() public {
        bytes memory assignments_blob = hex"1559afad11ba7ff3d55d143785c5eff549008c348b35ca61eaa6128b655512770999932d1a7506a758436fa6c95b03720e13c68d6cb1f5ed17a053c32acab0ab14ac314c00480dc9608454a6282c7ee4ab89c3af407b32df3742ff63b89817b408fa5c6a0b0652595588d141e9d7b235702354f1fb9649bccc96450f4a26ab09056218a26b3f380732b4abe9595ab3de6c4916340a01106d813f7983146b9d180a34193f84dd6355576bf80d58d04089bc3cc45a5f4db7aab67ea1bdcf160e0d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002bd3e90a8970cb5fc2e8d7384e001dee3bf7322f23fdf16b5bbb10beab706e5c000000000000000000000000000000000000000000000000000000000000000026d81a6b96b76bfad6cd9f409731fa9ff9fbd6d2fad63d5dd3fbafe8202fdbbe190390acb2c6b8865f64bac96231a4c06a6a0f9e945d2aa7cdde9664a026b2cf";
        types.gate_eval_params memory params;
        params.modulus = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001;
        params.theta = 26509649739312616830633500045428164374595609435618518653440390409995716485591;
        params.theta_acc = 1;
        uint256 theta_acc_result = 22776621096326636850168989734402224351450482466532466652833512923156695827432;
        uint256 gate_evaluation_result = 2187611903631573800010139566678334142237983618461939715906907249863037036657;
        uint256[] memory assignment_pointers = new uint256[](11);
        params.selector_evaluations_ptrs = new uint256[](1);
        assembly {
            let blob_ptr := add(assignments_blob, 0x20)
            let pointers_ptr := add(assignment_pointers, 0x20)
            for { let i := 0 } lt(i, 11) { i := add(i, 1) } {
                mstore(pointers_ptr, blob_ptr)
                blob_ptr := add(blob_ptr, 0x20)
                pointers_ptr := add(pointers_ptr, 0x20)
            }
            mstore(add(mload(add(params, 0x60)), 0x20), blob_ptr)
        }
        uint256 gate_evaluation = unified_addition_component.evaluate_gates_be(assignment_pointers, params);
        Assert.equal(theta_acc_result, params.theta_acc, "Theta accumulator result is not correct");
        Assert.equal(gate_evaluation_result, gate_evaluation, "Gate evaluation result is not correct");
    }

    function test_unified_addition_case2() public {
        bytes memory assignments_blob = hex"39f3a986276400916e750fc09bd0391b17f99219eced45f9ceed56d6e0a5af083a8f1a128aa1f62c57e60eb49e7ac2cfdac2b54b992d3cd293defe1aaaee4ac5336bbd898833f7a9a0d45661c9281522c589e14dd308f18cbef7c5f9a06ce4382702457223e10a24fc9817cffe152277b0749f064ac65dc58f15cc4d1488f5733a9ebbbaa845cf846d773ddcd6dbf28d45a34494a9b2cdf494a3d40bb716f02c15f707e897c2b014bd8b04df33d4fb9efabf8ae50ec70539904cefbfbb1449620000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010d220bc51d7953dc3144a7dfbe26f278b0baa035f5c350a590610f118c150090000000000000000000000000000000000000000000000000000000000000000176b8b63ed649bf0978cd3fd1980f0ce6fdd3bcda16dd1241427f0b626b000a503e7fa0423fe828b16a3afa307394cd424ee821b170e92e341a8b5b2a1daac4d";
        types.gate_eval_params memory params;
        params.modulus = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001;
        params.theta = 4067669573467535144587803642075215886243082585602738614737422003214610267888;
        params.theta_acc = 1;
        uint256 theta_acc_result = 24646083228986430749961998025613465618039050811281191453579094140630843188665;
        uint256 gate_evaluation_result = 14885472559964206998700281637416132659595071240967250098605268510205097507577;
        uint256[] memory assignment_pointers = new uint256[](11);
        params.selector_evaluations_ptrs = new uint256[](1);
        assembly {
            let blob_ptr := add(assignments_blob, 0x20)
            let pointers_ptr := add(assignment_pointers, 0x20)
            for { let i := 0 } lt(i, 11) { i := add(i, 1) } {
                mstore(pointers_ptr, blob_ptr)
                blob_ptr := add(blob_ptr, 0x20)
                pointers_ptr := add(pointers_ptr, 0x20)
            }
            mstore(add(mload(add(params, 0x60)), 0x20), blob_ptr)
        }
        uint256 gate_evaluation = unified_addition_component.evaluate_gates_be(assignment_pointers, params);
        Assert.equal(theta_acc_result, params.theta_acc, "Theta accumulator result is not correct");
        Assert.equal(gate_evaluation_result, gate_evaluation, "Gate evaluation result is not correct");
    }
}
