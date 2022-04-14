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

import "../types.sol";

/**
 * @title Transcript library
 * @dev Generates Plonk random challenges
 */
library transcript {
    function init_transcript(
        types.transcript_data memory self,
        bytes memory init_blob
    ) internal pure {
        self.current_challenge = keccak256(init_blob);
    }

    function update_transcript(
        types.transcript_data memory self,
        bytes memory blob
    ) internal pure {
        self.current_challenge = keccak256(
            bytes.concat(self.current_challenge, blob)
        );
    }

    function update_transcript_b32(
        types.transcript_data memory self,
        bytes32 blob
    ) internal pure {
        self.current_challenge = keccak256(
            bytes.concat(self.current_challenge, blob)
        );
    }

    function update_transcript_b32_by_offset(
        types.transcript_data memory self,
        bytes memory blob,
        uint256 offset
    ) internal pure {
        require(
            offset < blob.length,
            "update_transcript_b32_by_offset: offset < blob.length"
        );
        require(
            32 <= blob.length - offset,
            "update_transcript_b32_by_offset: 32 <= blob.length - offset"
        );

        bytes32 blob32;
        assembly {
            blob32 := mload(add(add(blob, 0x20), offset))
        }
        update_transcript_b32(self, blob32);
    }

    function update_transcript_b32_by_offset_calldata(
        types.transcript_data memory self,
        bytes calldata blob,
        uint256 offset
    ) internal pure {
        require(
            offset < blob.length,
            "update_transcript_b32_by_offset: offset < blob.length"
        );
        require(
            32 <= blob.length - offset,
            "update_transcript_b32_by_offset: 32 <= blob.length - offset"
        );

        bytes32 blob32;
        assembly {
            blob32 := calldataload(add(blob.offset, offset))
        }
        update_transcript_b32(self, blob32);
    }

    function get_integral_challenge_be(
        types.transcript_data memory self,
        uint256 length
    ) internal pure returns (uint256 result) {
        require(length <= 32);
        self.current_challenge = keccak256(
            abi.encodePacked(self.current_challenge)
        );
        return
            (uint256(self.current_challenge) &
                (((uint256(1) << (length * 8)) - 1) <<
                    (uint256(256) - length * 8))) >>
            (uint256(256) - length * 8);
    }

    function get_field_challenge(
        types.transcript_data memory self,
        uint256 modulus
    ) internal pure returns (uint256) {
        self.current_challenge = keccak256(abi.encode(self.current_challenge));
        return uint256(self.current_challenge) % modulus;
    }

    function get_field_challenges(
        types.transcript_data memory self,
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
