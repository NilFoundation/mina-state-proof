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

pragma solidity >=0.6.0;
pragma experimental ABIEncoderV2;

import "truffle/Assert.sol";
import '../contracts/cryptography/types.sol';
import '../contracts/components/unified_addition.sol';

contract TestUnifiedAddition {
    function test_unified_addition_case1() public {
        bytes memory assignments_blob = hex"0a3ead053ea9aba40c7db33a22aa393114a4f6e731afa76597790d08888624de266a03b1ac804d0502c225a37e54ee0e809a82c1a8bc09054fff0a946ccbe93d072437b67312771c06a087c0e05187eccdd6ede80a59dc8ed7c4ee83346154073aef6cb95f00fed8c6da6c35ac8b60de947d801445fbb2c68333ccf2a048eb832cf0ee621483f35673e4fc931114a4bc3c344a5c3637391ea2b1538708f4e25512c4fd6942564f5856f4f081bc68b3aa106d4386342f673fb237a682c7467885000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001f14f594ebac3dc9f81ed6d6dda41c64e9de88e8654737b7516568dd5432b3c6000000000000000000000000000000000000000000000000000000000000000032da6215fb1074903081bb0b255dd45b4bfec114bae38e3a03a1bd4294974d79";
        types.gate_evaluation_params memory params;
        params.modulus = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001;
        params.theta = 11995821600208401150293563360670110219894878178846176377891838760787383727711;
        params.theta_acc = 1;
        uint256 theta_acc_result = 18919757974252196026814859001418628515843809159227630427263085778189638536062;
        uint256 gate_evaluation_result = 26930449861150467942162112782312616668103152361483897786509581728808929933172;
        uint256[] memory assignment_pointers = new uint256[](11);
        assembly {
            let blob_ptr := add(assignments_blob, 0x20)
            let pointers_ptr := add(assignment_pointers, 0x20)
            for { let i := 0 } lt(i, 11) { i := add(i, 1) } {
                mstore(pointers_ptr, blob_ptr)
                blob_ptr := add(blob_ptr, 0x20)
                pointers_ptr := add(pointers_ptr, 0x20)
            }
        }
        uint256 gate_evaluation = unified_addition_component.evaluate_gate_be(assignment_pointers, params);
        Assert.equal(theta_acc_result, params.theta_acc, "Theta accumulator result is not correct");
        Assert.equal(gate_evaluation_result, gate_evaluation, "Gate evaluation result is not correct");
    }

    function test_unified_addition_case2() public {
        bytes memory assignments_blob = hex"2b6001111b5a079e3a0d2ba6d1ffb35408ee5a37f0e548556e827d9c834365a60cd613022ca041b9064cc7055ccaa8be5e8dabd1239345b464a200d28b574f181b24f5943b65f2b3b9ffe28a63652a09b7f2791cb3e75b08a7ead9707a45fc3620819e1b9f6ee2699fcd77878f4befdfd5c44463d9a9e61ac194e7324990ea4b038f19bdcbae6d6f781798d1cbfdb6777daa1df4ba02e20a790a86c519ebf3be00e7c11b8de8afec08a29996e055607fd630229028ad39711fd9032be21c7bf2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002419e8ad68b93159b308d498778b508991d7569e274ca3833b6e4ac5fa1c567100000000000000000000000000000000000000000000000000000000000000003dab5ff0195dbcdc86ec6a5b1e1ddb9d94b8d59ff5b1f7c707a179d7b1840072";
        types.gate_evaluation_params memory params;
        params.modulus = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001;
        params.theta = 1818095247743482794163972829438338158259475937805493705855939842964977456154;
        params.theta_acc = 1;
        uint256 theta_acc_result = 1487117479196530911789796787042369339233010771237463636540401155867641544490;
        uint256 gate_evaluation_result = 1708076078669318254389649679546128954723719317516501654162990559737622291944;
        uint256[] memory assignment_pointers = new uint256[](11);
        assembly {
            let blob_ptr := add(assignments_blob, 0x20)
            let pointers_ptr := add(assignment_pointers, 0x20)
            for { let i := 0 } lt(i, 11) { i := add(i, 1) } {
                mstore(pointers_ptr, blob_ptr)
                blob_ptr := add(blob_ptr, 0x20)
                pointers_ptr := add(pointers_ptr, 0x20)
            }
        }
        uint256 gate_evaluation = unified_addition_component.evaluate_gate_be(assignment_pointers, params);
        Assert.equal(theta_acc_result, params.theta_acc, "Theta accumulator result is not correct");
        Assert.equal(gate_evaluation_result, gate_evaluation, "Gate evaluation result is not correct");
    }
}
