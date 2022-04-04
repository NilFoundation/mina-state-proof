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

import '../types.sol';
import '../commitments/lpc_verifier.sol';
import '../basic_marshalling.sol';

library redshift_proof_map_parser {
    /**
     * Proof structure: https://github.com/NilFoundation/crypto3-zk-marshalling/blob/master/include/nil/crypto3/marshalling/zk/types/redshift/proof.hpp
     */
    function parse_be(
        bytes memory blob,
        uint256 offset
    )
    internal pure returns (types.redshift_proof_map memory proof_map, uint256 proof_size) {
        // skip v_perm_commitment
        proof_map.witness_commitments_offset = basic_marshalling.skip_octet_vector_32_be_check(blob, offset);
        // skip witness_commitments
        proof_map.T_commitments_offset = basic_marshalling.skip_vector_of_octet_vectors_32_be_check(blob, proof_map.witness_commitments_offset);
        // skip T_commitments
        proof_map.eval_proof_offset = basic_marshalling.skip_vector_of_octet_vectors_32_be_check(blob, proof_map.T_commitments_offset);
        // skip challenge
        proof_map.eval_proof_witness_offset = basic_marshalling.skip_uint256_be_check(blob, proof_map.eval_proof_offset);
        // skip witness
        proof_map.eval_proof_permutation_offset = lpc_verifier.skip_vector_of_proofs_be_check(blob, proof_map.eval_proof_witness_offset);
        // skip permutation
        proof_map.eval_proof_quotient_offset = lpc_verifier.skip_vector_of_proofs_be_check(blob, proof_map.eval_proof_permutation_offset);
        // skip quotient
        proof_map.eval_proof_id_permutation_offset = lpc_verifier.skip_vector_of_proofs_be_check(blob, proof_map.eval_proof_quotient_offset);
        // skip id_permutation
        proof_map.eval_proof_sigma_permutation_offset = lpc_verifier.skip_vector_of_proofs_be_check(blob, proof_map.eval_proof_id_permutation_offset);
        // skip sigma_permutation
        proof_map.eval_proof_public_input_offset = lpc_verifier.skip_vector_of_proofs_be_check(blob, proof_map.eval_proof_sigma_permutation_offset);
        // skip public_input
        proof_map.eval_proof_constant_offset = lpc_verifier.skip_vector_of_proofs_be_check(blob, proof_map.eval_proof_public_input_offset);
        // skip constant
        proof_map.eval_proof_selector_offset = lpc_verifier.skip_vector_of_proofs_be_check(blob, proof_map.eval_proof_constant_offset);
        // skip selector
        proof_map.eval_proof_special_selectors_offset = lpc_verifier.skip_vector_of_proofs_be_check(blob, proof_map.eval_proof_selector_offset);
        // skip special_selectors
        proof_size = lpc_verifier.skip_vector_of_proofs_be_check(blob, proof_map.eval_proof_special_selectors_offset) - offset;
    }
}
