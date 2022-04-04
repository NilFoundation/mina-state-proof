// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

import '../../types.sol';
import '../unified_addition.sol';

contract TestUnifiedAdditionComponent {
    types.gate_eval_params m_params;
    uint256 public m_evaluation_result;
    uint256 public m_theta_acc;

    function set_params(uint256 modulus, uint256 theta) public {
        m_params.modulus = modulus;
        m_params.theta_acc = 1;
        m_params.theta = theta;
    }

    function evaluate(bytes memory assignments_blob) public {
        types.gate_eval_params memory params = m_params;
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

        m_evaluation_result = unified_addition_component.evaluate_gates_be(assignment_pointers, params);
        m_theta_acc = params.theta_acc;
    }
}
