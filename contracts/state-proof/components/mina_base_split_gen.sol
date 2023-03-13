// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

import "@nilfoundation/evm-placeholder-verification/contracts/types.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/basic_marshalling.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/commitments/batched_lpc_verifier.sol";
//TODO : Changed
import "@nilfoundation/evm-placeholder-verification/contracts/interfaces/gate_argument.sol";

import "./mina_base/mina_base_gate0.sol";
import "./mina_base/mina_base_gate1.sol";
import "./mina_base/mina_base_gate2.sol";
import "./mina_base/mina_base_gate3.sol";
import "./mina_base/mina_base_gate4.sol";
import "./mina_base/mina_base_gate5.sol";
import "./mina_base/mina_base_gate6.sol";
import "./mina_base/mina_base_gate7.sol";
import "./mina_base/mina_base_gate8.sol";
import "./mina_base/mina_base_gate9.sol";
import "./mina_base/mina_base_gate10.sol";
import "./mina_base/mina_base_gate11.sol";
import "./mina_base/mina_base_gate12.sol";
import "./mina_base/mina_base_gate13.sol";
import "./mina_base/mina_base_gate14.sol";
import "./mina_base/mina_base_gate15.sol";
import "./mina_base/mina_base_gate16.sol";
import "./mina_base/mina_base_gate16_1.sol";
import "./mina_base/mina_base_gate17.sol";
import "./mina_base/mina_base_gate18.sol";

// TODO: name component
library mina_base_split_gen {
    // TODO: specify constants
    uint256 constant GATES_N = 23;


    // TODO: columns_rotations could be hard-coded
    function evaluate_gates_be(
        bytes calldata blob,
        types.gate_argument_local_vars memory gate_params,
        types.arithmetization_params memory ar_params,
        int256[][] memory columns_rotations
    ) internal returns (uint256 gates_evaluation) {
        // TODO: check witnesses number in proof
        profiling.start_block("mina_base_split_gen:evaluate_gates_be");

        gate_params.witness_evaluations = new uint256[][](ar_params.witness_columns);
        gate_params.offset = batched_lpc_verifier.skip_to_z(blob,  gate_params.eval_proof_witness_offset);
        for (uint256 i = 0; i < ar_params.witness_columns; i++) {
            gate_params.witness_evaluations[i] = new uint256[](columns_rotations[i].length);
            for (uint256 j = 0; j < columns_rotations[i].length; j++) {
                gate_params.witness_evaluations[i][j] = basic_marshalling.get_i_j_uint256_from_vector_of_vectors(blob, gate_params.offset, i, j);
            }
        }

        gate_params.selector_evaluations = new uint256[](GATES_N);
        gate_params.offset = batched_lpc_verifier.skip_to_z(blob,  gate_params.eval_proof_selector_offset);
        for (uint256 i = 0; i < GATES_N; i++) {
            gate_params.selector_evaluations[i] = basic_marshalling.get_i_j_uint256_from_vector_of_vectors(
                blob, 
                gate_params.offset, 
                i + ar_params.permutation_columns + ar_params.permutation_columns + ar_params.constant_columns, 
                0
            );
        }

        gate_params.constant_evaluations = new uint256[][](ar_params.constant_columns);
        gate_params.offset = batched_lpc_verifier.skip_to_z(blob,  gate_params.eval_proof_constant_offset);
        for (uint256 i = 0; i < ar_params.constant_columns; i++) {
            gate_params.constant_evaluations[i] = new uint256[](columns_rotations[i].length);
            for (uint256 j = 0; j < columns_rotations[i].length; j++) {
                gate_params.constant_evaluations[i][j] = basic_marshalling.get_i_j_uint256_from_vector_of_vectors(
                    blob, 
                    gate_params.offset, 
                    i + ar_params.permutation_columns + ar_params.permutation_columns, 
                    j
                );
            }
        }

        gate_params.theta_acc = 1;
        gate_params.gates_evaluation = 0;
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate0.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate1.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate2 .evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate3.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate4.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate5.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate6.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate7.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate8.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate9.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate10.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate11.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate12.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate13.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate14.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate15.evaluate_gate_be(gate_params);
        (gate_params.gate_eval, gate_params.theta_acc) = mina_base_gate16.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate16_1.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate17.evaluate_gate_be(gate_params);
        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate18.evaluate_gate_be(gate_params);
//      This last contain gate18
//        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate19.evaluate_gate_be(gate_params);
//        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate20.evaluate_gate_be(gate_params);
//        (gate_params.gates_evaluation, gate_params.theta_acc) = mina_base_gate21.evaluate_gate_be(gate_params);

        gates_evaluation = gate_params.gates_evaluation;
        profiling.end_block();
    }
}