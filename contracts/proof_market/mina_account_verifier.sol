// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2023 Haresh G <hgedia@nil.foundation>
// Copyright (c) 2023 Amit Sagar <asagar@nil.foundation>
// Copyright (c) 2023 Ilia Shirobokov <i.shirobokov@nil.foundation>
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
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import '@nilfoundation/evm-placeholder-verification/contracts/interfaces/verifier.sol';
import "../interfaces/IProofMarketVerifier.sol";


contract AccountPathVerifier is IProofMarketVerifier, Ownable {

    address _verifier;
    address _gates;
    uint256[] _init_params;
    int256[][] _columns_rotations;

    constructor(address verifier, address gates, uint256[] memory init_params, int256[][] memory columns_rotations) {
        _verifier = verifier;
        _gates = gates;
        _init_params = init_params;
        _columns_rotations = columns_rotations;
    }

    function setVerifier(address verifier) external onlyOwner {
        _verifier = verifier;
    }

    function setGates(address gates) external onlyOwner {
        _gates = gates;
    }

    function setInitParams(uint256[] memory init_params) external onlyOwner {
        _init_params = init_params;
    }

    function setColumnsRotations(int256[][] memory columns_rotations) external onlyOwner {
        _columns_rotations = columns_rotations;
    }

    function verify(bytes calldata blob, uint256[] calldata public_input) external view returns (bool) {
        IVerifier v = IVerifier(_verifier);
        return v.verify(blob, _init_params, _columns_rotations, _gates);
    }
}