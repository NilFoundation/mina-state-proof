// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2023 Mikhail Komarov <nemo@nil.foundation>
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

import "@openzeppelin/contracts/access/Ownable.sol";

import '@nilfoundation/evm-placeholder-verification/contracts/interfaces/verifier.sol';
import '@nilfoundation/evm-placeholder-verification/contracts/verifier.sol';

contract MinaStateProof is Ownable {
    address _verifier;

    address _base_gates;
    address _scalar_gates;

    IVerifier v;

    constructor(address verifier, address base_gates, address scalar_gates) {
        _verifier = verifier;
        _base_gates = base_gates;
        _scalar_gates = scalar_gates;

        v = IVerifier(_verifier);
    }

    function setVerifier(address verifier) external onlyOwner {
        _verifier = verifier;
        v = IVerifier(_verifier);
    }

    function setBaseGates(address base_gates) external onlyOwner {
        _base_gates = base_gates;
    }

    function setScalarGates(address scalar_gates) external onlyOwner {
        _scalar_gates = scalar_gates;
    }

    function verify(bytes calldata blob, uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations, uint256[][] calldata public_inputs) external view returns (bool) {
        uint256 size1 = init_params[0][0];
        uint256 size2 = init_params[0][1];

        return size1 + size2 == blob.length &&
        v.verify(
            blob[0 : size1], init_params[1], columns_rotations[0], public_inputs[0], _base_gates
        ) &&
        v.verify(
            blob[size1 : blob.length],  init_params[2], columns_rotations[1], public_inputs[1], _scalar_gates
        );
    }
}
