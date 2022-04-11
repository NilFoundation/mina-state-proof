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
pragma solidity >=0.8.4;

import "../types.sol";

library merkle_verifier_calldata {
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
    uint256 constant DEPTH_OFFSET = 48;
    uint256 constant LAYERS_OFFSET = 56;
    // only one co-element on each layer as arity is always 2
    // 8 + (number of co-path elements on the layer)
    // 8 + (co-path element position on the layer)
    // 8 + (co-path element hash value length)
    // 32 (co-path element hash value)
    uint256 constant LAYER_OCTETS = 56;

    function skip_merkle_proof_be(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 result_offset)
    {
        result_offset = offset + LAYERS_OFFSET;
        assembly {
            result_offset := add(
                result_offset,
                mul(
                    LAYER_OCTETS,
                    shr(
                        0xc0,
                        calldataload(
                            add(blob.offset, add(offset, DEPTH_OFFSET))
                        )
                    )
                )
            )
        }
    }

    function skip_merkle_proof_be_check(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 result_offset)
    {
        result_offset = offset + LAYERS_OFFSET;
        require(result_offset < blob.length);
        assembly {
            result_offset := add(
                result_offset,
                mul(
                    LAYER_OCTETS,
                    shr(
                        0xc0,
                        calldataload(
                            add(blob.offset, add(offset, DEPTH_OFFSET))
                        )
                    )
                )
            )
        }
        require(result_offset <= blob.length, "skip_merkle_proof_be");
    }

    function parse_verify_merkle_proof_be(
        bytes calldata blob,
        uint256 offset,
        bytes32 verified_data
    ) internal pure returns (bool result, uint256 proof_size) {
        bytes32 root;
        assembly {
            root := calldataload(add(blob.offset, add(offset, 16)))
        }

        uint256 depth;
        assembly {
            depth := shr(0xc0, calldataload(add(blob.offset, add(offset, 48))))
        }

        proof_size = LAYERS_OFFSET + LAYER_OCTETS * depth;
        uint256 layer_offset = offset + LAYERS_OFFSET;
        uint256 layer_hash_offset = 0;

        // hash verified_data to get corresponding merkle tree leaf
        assembly {
            let first_pos := shr(
                0xc0,
                calldataload(add(blob.offset, add(layer_offset, 8)))
            )
            mstore(0, verified_data)
            switch first_pos
            case 0 {
                mstore(0x20, keccak256(0, 0x20))
            }
            case 1 {
                mstore(0x00, keccak256(0, 0x20))
            }
        }

        for (uint256 cur_layer_i = 0; cur_layer_i < depth - 1; cur_layer_i++) {
            layer_offset = offset + LAYERS_OFFSET + LAYER_OCTETS * cur_layer_i;
            layer_hash_offset = layer_offset + 24;
            assembly {
                let pos := shr(
                    0xc0,
                    calldataload(add(blob.offset, add(layer_offset, 8)))
                )
                let next_pos := shr(
                    0xc0,
                    calldataload(
                        add(
                            blob.offset,
                            add(add(layer_offset, 8), LAYER_OCTETS)
                        )
                    )
                )
                switch pos
                case 0 {
                    mstore(
                        0x00,
                        calldataload(add(blob.offset, layer_hash_offset))
                    )
                    switch next_pos
                    case 0 {
                        mstore(0x20, keccak256(0, 0x40))
                    }
                    case 1 {
                        mstore(0, keccak256(0, 0x40))
                    }
                }
                case 1 {
                    mstore(
                        0x20,
                        calldataload(add(blob.offset, layer_hash_offset))
                    )
                    switch next_pos
                    case 0 {
                        mstore(0x20, keccak256(0, 0x40))
                    }
                    case 1 {
                        mstore(0, keccak256(0, 0x40))
                    }
                }
            }
        }

        layer_offset = offset + LAYERS_OFFSET + LAYER_OCTETS * (depth - 1);
        layer_hash_offset = layer_offset + 24;
        assembly {
            let pos := shr(
                0xc0,
                calldataload(add(blob.offset, add(layer_offset, 8)))
            )
            switch pos
            case 0 {
                mstore(0x00, calldataload(add(blob.offset, layer_hash_offset)))
                verified_data := keccak256(0, 0x40)
            }
            case 1 {
                mstore(0x20, calldataload(add(blob.offset, layer_hash_offset)))
                verified_data := keccak256(0, 0x40)
            }
        }

        result = (verified_data == root);
    }
}
