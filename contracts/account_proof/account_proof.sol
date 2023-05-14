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

import "@openzeppelin/contracts/access/Ownable.sol";

import '@nilfoundation/evm-placeholder-verification/contracts/interfaces/verifier.sol';
import '@nilfoundation/evm-placeholder-verification/contracts/verifier.sol';

import "./gates/gate_argument.sol";


contract AccountPathProof is Ownable {

    address _verifier;

    address _gates;

    constructor(address verifier, address gates) {
        _verifier = verifier;
        _gates = gates;
    }

    function setVerifier(address verifier) external onlyOwner {
        _verifier = verifier;
    }

    function setGates(address gates) external onlyOwner {
        _gates = gates;
    }

    function verify(bytes calldata blob, uint256[] calldata init_params,
        int256[][] calldata columns_rotations) external view returns (bool) {

        IVerifier v = IVerifier(_verifier);

        return v.verify(blob, init_params, columns_rotations, _gates);
    }
}