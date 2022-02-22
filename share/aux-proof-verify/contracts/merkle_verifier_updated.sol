// SPDX-License-Identifier: Apache-2.0.
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

import "./fri_layer.sol";

library merkle_verifier_updated {

    // Merkle proof has the following structure:
    // [0:8] - leaf index
    // [8:16] - root length (which is always 32 bytes in current implementation)
    // [16:48] - root
    // [48:56] - merkle tree depth
    //
    // Depth number of layers with co-path elements follows then.
    // Each layer has following structure (actually indexes begin from a certain offset):
    // [0:8] - number of co-path elements on the layer
    //  (layer_size = arity-1 actually, which (arity) is always 2 in current implementation)
    //
    // layer_size number of co-path elements for every layer in merkle proof follows then.
    // Each element has following structure (actually indexes begin from a certain offset):
    // [0:8] - co-path element position on the layer
    // [8:16] - co-path element hash value length (which is always 32 bytes in current implementation)
    // [16:48] - co-path element hash value
    function verify_merkle_proof(
        bytes memory merkle_proof,
        bytes memory verified_data
    ) internal pure returns (bool result) {

        bytes32 prev_hash = keccak256(verified_data);
        uint256 depth = 0;
        for (uint256 i = 48; i < 56; i++) {
            depth <<= 8;
            depth |= uint256(uint8(merkle_proof[i]));
        }
        uint256 layers_offset = 56;
        uint256 layer_size = 8 + 8 + 8 + 32;
        bytes memory co_path_element = new bytes(32);
        uint256 layer_offset = 0;
        uint256 co_path_element_pos = 0;
        for (uint256 cur_row = 0; cur_row < depth; cur_row++) {
            layer_offset = layers_offset + layer_size * cur_row;
            co_path_element_pos = 0;
            for (uint256 i = layer_offset + 8; i < layer_offset + 16; i++) {
                co_path_element_pos <<= 8;
                co_path_element_pos |= uint256(uint8(merkle_proof[i]));
            }
            for (uint256 i = layer_offset + 24; i < layer_offset + 56; i++) {
                co_path_element[i - layer_offset - 24] = merkle_proof[i];
            }
            if (0 == co_path_element_pos) {
                prev_hash = keccak256(bytes.concat(co_path_element, prev_hash));
            }
            else if (1 == co_path_element_pos) {
                prev_hash = keccak256(bytes.concat(prev_hash, co_path_element));
            }
        }

        bool result = true;
        for (uint256 i = 16; i < 48; i++) {
            result = result && (merkle_proof[i] == prev_hash[i - 16]);
        }
        return result;
    }
}
