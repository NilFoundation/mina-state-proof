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

library merkle_verifier_adapted {

    struct path_element {
        uint256 position;
        bytes32 hash;
    }

    struct merkle_proof {
        uint256 li;
        bytes32 root;
        path_element[] path;
    }

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
    function parse_merkle_proof_be(bytes memory raw_proof) internal pure returns (merkle_proof memory proof) {
        proof.li = 0;
        for (uint256 i = 0; i < 8; i++) {
            proof.li <<= 8;
            proof.li |= uint256(uint8(raw_proof[i]));
        }

        uint256 root_length = 0;
        for (uint256 i = 8; i < 16; i++) {
            root_length <<= 8;
            root_length |= uint256(uint8(raw_proof[i]));
        }
        require(root_length == 32);

        bytes32 hash_value;
        assembly {
            hash_value := mload(add(add(raw_proof, 0x20), 16))
        }
        proof.root = hash_value;

        uint256 depth = 0;
        for (uint256 i = 48; i < 56; i++) {
            depth <<= 8;
            depth |= uint256(uint8(raw_proof[i]));
        }
        path_element[] memory path = new path_element[](depth);
        uint256 layers_offset = 56;
        uint256 layer_size = 8   // number of co-path elements on the layer
                           + 8   // co-path element position on the layer
                           + 8   // co-path element hash value length
                           + 32; // co-path element hash value
        bytes memory co_path_element = new bytes(32);
        uint256 layer_offset = 0;
        for (uint256 cur_layer_i = 0; cur_layer_i < depth; cur_layer_i++) {
            // only one co-element on each layer as arity is always 2
            layer_offset = layers_offset + layer_size * cur_layer_i;
            path[cur_layer_i].position = 0;
            for (uint256 i = layer_offset + 8; i < layer_offset + 16; i++) {
                path[cur_layer_i].position <<= 8;
                path[cur_layer_i].position |= uint256(uint8(raw_proof[i]));
            }

            assembly {
                hash_value := mload(add(add(add(raw_proof, 0x20), layer_offset), 24))
            }
            path[cur_layer_i].hash = hash_value;
        }
        proof.path = path;
    }

    function verify_merkle_proof(
        merkle_proof memory proof,
        bytes32 verified_data
    ) internal pure returns (bool) {

        bytes32 prev_hash = keccak256(abi.encode(verified_data));
        for (uint256 cur_layer_i = 0; cur_layer_i < proof.path.length; cur_layer_i++) {
            if (0 == proof.path[cur_layer_i].position) {
                prev_hash = keccak256(bytes.concat(proof.path[cur_layer_i].hash, prev_hash));
            }
            else if (1 == proof.path[cur_layer_i].position) {
                prev_hash = keccak256(bytes.concat(prev_hash, proof.path[cur_layer_i].hash));
            }
        }

        return prev_hash == proof.root;
    }
}
