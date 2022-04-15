// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

import '../../types.sol';
import '../merkle_verifier_calldata.sol';

contract TestMerkleProofVerifier {
    bool m_result;
    uint256 m_proof_size;

    function verify(bytes calldata raw_proof, bytes32 verified_data) public {
        (m_result, m_proof_size) = merkle_verifier_calldata.parse_verify_merkle_proof_be(raw_proof, 0, verified_data);
        require(raw_proof.length == m_proof_size, "Merkle proof length if incorrect!");
        require(raw_proof.length == merkle_verifier_calldata.skip_merkle_proof_be(raw_proof, 0), "Merkle proof length if incorrect!");
        require(raw_proof.length == merkle_verifier_calldata.skip_merkle_proof_be_check(raw_proof, 0), "Merkle proof length if incorrect!");
        require(m_result, "Merkle proof is not correct!");
    }
}
