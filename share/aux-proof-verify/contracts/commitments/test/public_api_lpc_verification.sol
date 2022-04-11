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
import "../lpc_verifier_calldata.sol";
import "../../cryptography/transcript.sol";

contract TestLpcVerifier {
    bool m_result;
    uint256 m_proof_size;
    types.lpc_params_type m_params;

    function set_params(
        uint256 modulus,
        uint256 r,
        uint256 max_degree,
        uint256 lambda,
        uint256 m
    ) public {
        m_params.modulus = modulus;
        m_params.lambda = lambda;
        m_params.r = r;
        m_params.m = m;

        m_params.fri_params.modulus = modulus;
        m_params.fri_params.r = r;
        m_params.fri_params.max_degree = max_degree;
    }

    function set_q(uint256[] calldata q) public {
        m_params.fri_params.q = q;
    }

    function set_D_omegas(uint256[] calldata D_omegas) public {
        m_params.fri_params.D_omegas = D_omegas;
    }

    function set_U(uint256[] calldata U) public {
        m_params.fri_params.U = U;
    }

    function set_V(uint256[] calldata V) public {
        m_params.fri_params.V = V;
    }

    // TODO: optimize - do not copy params from storage to memory
    function verify(
        bytes calldata raw_proof,
        bytes calldata init_transcript_blob,
        uint256[] calldata evaluation_points
    ) public {
        types.transcript_data memory tr_state;
        transcript.init_transcript(tr_state, init_transcript_blob);
        (m_result, m_proof_size) = lpc_verifier_calldata.parse_verify_proof_be(
            raw_proof,
            0,
            evaluation_points,
            tr_state,
            m_params
        );
        require(
            raw_proof.length == m_proof_size,
            "LPC proof length if incorrect!"
        );
        require(m_result, "LPC proof is not correct!");
        require(
            raw_proof.length ==
                lpc_verifier_calldata.skip_proof_be(raw_proof, 0),
            "LPC proof length if incorrect!"
        );
        require(
            raw_proof.length ==
                lpc_verifier_calldata.skip_proof_be_check(raw_proof, 0),
            "LPC proof length if incorrect!"
        );
    }
}
