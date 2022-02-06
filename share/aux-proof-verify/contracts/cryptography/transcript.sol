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

import './types.sol';

/**
 * @title Transcript library
 * @dev Generates Plonk random challenges
 */
library transcript {

    struct transcript_data {
        bytes32 current_challenge;
    }

    function init_transcript(
        transcript_data memory self,
        uint256 circuit_size,
        uint256 num_public_inputs
    ) internal pure {
        bytes32 challenge;
        assembly {
            let mPtr := mload(0x40)
            mstore8(add(mPtr, 0x20), shr(24, circuit_size))
            mstore8(add(mPtr, 0x21), shr(16, circuit_size))
            mstore8(add(mPtr, 0x22), shr(8, circuit_size))
            mstore8(add(mPtr, 0x23), circuit_size)
            mstore8(add(mPtr, 0x24), shr(24, num_public_inputs))
            mstore8(add(mPtr, 0x25), shr(16, num_public_inputs))
            mstore8(add(mPtr, 0x26), shr(8, num_public_inputs))
            mstore8(add(mPtr, 0x27), num_public_inputs)
            challenge := keccak256(add(mPtr, 0x20), 0x08)
        }
        self.current_challenge = challenge;
    }

    function update_transcript(
        transcript_data memory self,
        bytes memory blob
    ) internal pure {
        self.current_challenge = keccak256(bytes.concat(self.current_challenge, blob));
    }

    function get_field_challenge(
        transcript_data memory self,
        uint256 modulus
    ) internal pure returns (uint256) {
        self.current_challenge = keccak256(abi.encode(self.current_challenge));
        return uint256(self.current_challenge) % modulus;
    }

    function get_field_challenges(
        transcript_data memory self,
        uint256[] memory challenges,
        uint256 modulus
    ) internal pure {
        if (challenges.length > 0) {
            bytes32 new_challenge = self.current_challenge;
            for (uint256 i = 0; i < challenges.length; i++) {
                new_challenge = keccak256(abi.encode(new_challenge));
                challenges[i] = uint256(new_challenge) % modulus;
            }
            self.current_challenge = new_challenge;
        }
    }
}
