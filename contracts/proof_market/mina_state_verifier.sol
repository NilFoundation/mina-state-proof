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
import "../interfaces/ICustomVerifier.sol";


contract MinaStateVerifier is ICustomVerifier, Ownable {
    address _verifier;

    address _base_gates;
    address _scalar_gates;
    uint256[][] _init_params;
    int256[][][] _columns_rotations;

    IVerifier v;

    constructor(
        address verifier,
        address base_gates,
        address scalar_gates,
        uint256[][] memory init_params,
        int256[][][] memory columns_rotations
    ) {
        _verifier = verifier;
        _base_gates = base_gates;
        _scalar_gates = scalar_gates;
        _init_params = init_params;
        _columns_rotations = columns_rotations;

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

    function setInitParams(uint256[][] memory init_params) external onlyOwner {
        _init_params = init_params;
    }

    function setColumnsRotations(int256[][][] memory columns_rotations) external onlyOwner {
        _columns_rotations = columns_rotations;
    }

    function verify(
        bytes calldata blob,
        // TODO: add public_inputs
        uint256[] calldata public_input
    ) external view returns (bool) {
        uint256 size1 = _init_params[0][0];
        uint256 size2 = _init_params[0][1];

        return size1 + size2 == blob.length &&
        v.verify(blob[0 : size1],
            _init_params[1], _columns_rotations[0], _base_gates) &&
        v.verify(blob[size1 : blob.length],
            _init_params[2], _columns_rotations[1], _scalar_gates);
    }
}
