// SPDX-License-Identifier: MIT OR Apache-2.0
//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

import '../types.sol';

import './redshift_vk.sol';

/**
 * @title Verification keys library
 * @dev Used to select the appropriate verification key for the proof in question
 */
library verification_keys {
    /**
     * @param _keyId - verification key identifier used to select the appropriate proof's key
     * @return Verification key
     */
    function getKeyById(uint256 _keyId) external pure returns (types.verification_key memory) {
        // added in order: qL, qR, qO, qC, qM. x coord first, followed by y coord
        types.verification_key memory vk;

        if (_keyId == 0) {
            vk = redshift_vk.get_verification_key();
        }
        return vk;
    }
}
