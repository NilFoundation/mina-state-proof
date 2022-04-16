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

import "../../types.sol";
import "../poseidon_split_gen.sol";
import "../../redshift/proof_map_parser_calldata.sol";

contract TestPoseidonComponentSplitGen {
    uint256 public m_evaluation_result;

    function evaluate(
        bytes calldata blob,
        uint256 modulus,
        uint256 theta,
        int256[][] calldata columns_rotations
    ) public {
        (
            types.redshift_proof_map_calldata memory proof_map,
            uint256 proof_size
        ) = redshift_proof_map_parser_calldata.parse_be(blob, 0);
        require(
            proof_size == blob.length,
            "Proof length was detected incorrectly!"
        );
        types.gate_argument_local_vars memory gate_params;
        gate_params.modulus = modulus;
        gate_params.theta = theta;
        gate_params.eval_proof_witness_offset = proof_map
            .eval_proof_witness_offset;
        gate_params.eval_proof_selector_offset = proof_map
            .eval_proof_selector_offset;

        // m_evaluation_result =
        poseidon_split_gen
            .evaluate_gates_be(blob, gate_params, columns_rotations);
    }
}
