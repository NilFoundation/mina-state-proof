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

import '@nilfoundation/evm-placeholder-verification/contracts/interfaces/verifier.sol';

contract MinaStateProof {
    function verify(bytes calldata blob, uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations, address verifier_address,
        address[2] calldata gate_arguments
    ) external view returns (bool) {
        uint256 size1 = init_params[0][0];
        uint256 size2 = init_params[0][1];

        if( size1 + size2 != blob.length) {
            return false;
        }

        // Base proof verification
        if( !IVerifier(verifier_address).verify(blob[0:init_params[0][0]], init_params[1], columns_rotations[0], gate_arguments[0]) ) return false;
        // Scalar proof verification
        if( !IVerifier(verifier_address).verify(blob[init_params[0][0]: blob.length], init_params[2], columns_rotations[1], gate_arguments[1]) ) return false;

        return true;
    }
}
