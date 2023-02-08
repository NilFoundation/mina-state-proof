// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2023 Amit Sagar <asagar@nil.foundation>
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

import "@nilfoundation/evm-placeholder-verification/contracts/interfaces/verifier.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/types.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/logging.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/profiling.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/cryptography/transcript.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/placeholder/proof_map_parser.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/placeholder/placeholder_verifier.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/placeholder/init_vars.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/containers/merkle_verifier.sol";
import "../contracts/state-proof/components/mina_base_split_gen.sol";
import "../contracts/state-proof/components/mina_scalar_split_gen.sol";
import "../contracts/state-proof/mina_state_proof.sol";
import "./state.sol";
import "./mina.sol";
import "./constants.sol"

contract TestVerifierMinaZKState {

    // logging.gase_usage emit events will be thrown too.
    event gas_usage_emit(uint8 command, string function_name, uint256 gas_usage);

    state.protocol s;
    state.commitlog c;
    uint256 ledger_hash;
    uint256 current_ledger_hash;

    function setState(state.protocol memory _s) public {
        s = _s;
    }

    function getState() public returns (uint256) {
        ledger_hash = s.previous_state_hash;
    }


    function verifyzkState(
        bytes calldata blob,
        uint256[] calldata init_params,
        int256[][] calldata columns_rotations,
        ledger_hash,bytes byte_fields
    ) public {
        profiling.start_block("public_api_mina_base_component::verify");
        init_vars.vars_t memory vars;
        init_vars.init(blob, init_params, columns_rotations, vars);

        types.placeholder_local_variables memory local_vars;
        // 3. append variable values commitments to transcript
        transcript.update_transcript_b32_by_offset_calldata(vars.tr_state, blob, basic_marshalling.skip_length(vars.proof_map.variable_values_commitment_offset));

        // 4. prepare evaluations of the polynomials that are copy-constrained

        // 5. permutation argument
        profiling.start_block("public_api_mina_base_component::permutation_argument");
        local_vars.permutation_argument = permutation_argument.verify_eval_be(blob, vars.tr_state,
            vars.proof_map, vars.fri_params,
            vars.common_data, local_vars, vars.arithmetization_params);
        profiling.end_block();

        // 7. gate argument specific for circuit
        profiling.start_block("public_api_mina_base_component::gate_argument");
        types.gate_argument_local_vars memory gate_params;
        gate_params.modulus = vars.fri_params.modulus;
        gate_params.theta = transcript.get_field_challenge(vars.tr_state, vars.fri_params.modulus);
        gate_params.eval_proof_witness_offset = vars.proof_map.eval_proof_variable_values_offset;
        gate_params.eval_proof_selector_offset = vars.proof_map.eval_proof_fixed_values_offset;
        gate_params.eval_proof_constant_offset = vars.proof_map.eval_proof_fixed_values_offset;

        local_vars.gate_argument = mina_base_split_gen.evaluate_gates_be(blob, gate_params, vars.arithmetization_params, vars.common_data.columns_rotations);
        profiling.end_block();

        if (merkle_verifier.parse_verify_merkle_proof_bytes_be(
                blob, 
                init_params, 
                byte_fields, ledger_hash)
            ) {
                require(true, "Merkle proof passed");
              //  return data // todo
               
        }


        else if (!merkle_verifier.parse_verify_merkle_proof_bytes_be(
                blob, 
                init_params, 
                byte_fields, ledger_hash)
            ) {
                require(false, "Merkle proof failed");
                return false;
               
        }

        // if(ledger_hash includes in currentState){

        // }

        require(
            placeholder_verifier.verify_proof_be(
                blob,
                vars.tr_state,
                vars.proof_map,
                vars.fri_params,
                vars.common_data,
                local_vars,
                vars.arithmetization_params
            ),
            "Proof is not correct!"
        );
        profiling.end_block();
        profiling.end_block();
        return true;
    }

    function verify_mina_state(uint256 ledger_hash, bytes proof) returns (bool) {
          if(c.staged_ledger_hash == ledger_hash){
            return true;
          }
    }

    function verify_account(uint256 ledger_hash, bytes proof, bytes account_state) returns (bool) {
           if(p.blockchain_state == account_state) {
            returns true;
           }

    }

    function verify_zk_app_state_against_current_state(bytes proof, bytes account_state, bytes fields) returns (bool) { 
    ledger = state.current_ledger_hash;
        verify_account(uint256 ledger, bytes proof, bytes account_state)
    
    }
}
