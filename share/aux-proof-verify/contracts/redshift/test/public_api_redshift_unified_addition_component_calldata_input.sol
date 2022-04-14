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
import "../../cryptography/transcript.sol";
import "../proof_map_parser_calldata.sol";
import "../verifier_unified_addition_component_calldata.sol";

contract TestRedshiftVerifierUnifiedAdditionCalldataInput {
    struct test_local_vars {
        types.redshift_proof_map_calldata proof_map;
        uint256 proof_size;
        types.transcript_data tr_state;
        types.lpc_params_type lpc_params;
        types.redshift_common_data common_data;
    }
    bool public m_result;

    function verify(
        bytes calldata blob,
        // [modulus, lambda, r, m, max_degree, rows_amount, omega]
        uint256[] calldata params,
        uint256[] calldata D_omegas,
        uint256[] calldata q,
        int256[][] calldata columns_rotations
    ) public {
        test_local_vars memory vars;
        (vars.proof_map, vars.proof_size) = redshift_proof_map_parser_calldata
            .parse_be(blob, 0);
        require(
            vars.proof_size == blob.length,
            "Proof length was detected incorrectly!"
        );
        transcript.init_transcript(vars.tr_state, hex"");
        vars.lpc_params.modulus = params[0];
        vars.lpc_params.lambda = params[1];
        vars.lpc_params.r = params[2];
        vars.lpc_params.m = params[3];
        vars.lpc_params.fri_params.D_omegas = D_omegas;
        vars.lpc_params.fri_params.q = q;

        vars.lpc_params.fri_params.modulus = params[0];
        vars.lpc_params.fri_params.max_degree = params[4];
        vars.lpc_params.fri_params.r = params[2];

        vars.common_data.rows_amount = params[5];
        vars.common_data.omega = params[6];
        vars.common_data.columns_rotations = columns_rotations;

        m_result =
        redshift_verifier_unified_addition_component_calldata
            .verify_proof_be(
                blob,
                vars.tr_state,
                vars.proof_map,
                vars.lpc_params,
                vars.common_data
            );
        require(m_result, "Proof is not correct!");
    }
}
