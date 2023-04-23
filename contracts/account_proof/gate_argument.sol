
// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova  <alalmoskvin@nil.foundation>
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

import "@nilfoundation/evm-placeholder-verification//contracts/types.sol";
import "@nilfoundation/evm-placeholder-verification//contracts/profiling.sol";
import "@nilfoundation/evm-placeholder-verification//contracts/basic_marshalling.sol";
import "@nilfoundation/evm-placeholder-verification//contracts/commitments/batched_lpc_verifier.sol";
import "@nilfoundation/evm-placeholder-verification//contracts/gate_argument_interface.sol";

import "./gates/gate0.sol";
import "./gates/gate1.sol";
import "./gates/gate2.sol";
import "./gates/gate3.sol";
import "./gates/gate4.sol";
import "./gates/gate5.sol";
import "./gates/gate6.sol";
import "./gates/gate7.sol";
import "./gates/gate8.sol";
import "./gates/gate9.sol";
import "./gates/sgate10.sol";


contract account_gate_argument  is IGateArgument{
    // TODO: specify constants
    uint256 constant GATES_N = 11;

    // TODO: columns_rotations could be hard-coded
    function evaluate_gates_be(
        bytes calldata blob,
        types.gate_argument_local_vars memory gate_params,
        uint256 eval_proof_combined_value_offset,
        types.arithmetization_params memory ar_params,
        int256[][] calldata columns_rotations
    ) external view returns (uint256 gates_evaluation) {
        // TODO: check witnesses number in proof
        gate_params.witness_evaluations = new uint256[][](ar_params.witness_columns);
        for (uint256 i = 0; i < ar_params.witness_columns;) {
            gate_params.witness_evaluations[i] = new uint256[](columns_rotations[i].length);
            for (uint256 j = 0; j < columns_rotations[i].length;) {
                gate_params.witness_evaluations[i][j] = batched_lpc_verifier.get_variable_values_z_i_j_from_proof_be(
                    blob, eval_proof_combined_value_offset, i, j
                );
                unchecked{j++;}
            }
            unchecked{i++;}
        }

        gate_params.selector_evaluations = new uint256[](GATES_N);
        for (uint256 i = 0; i < GATES_N;) {
            gate_params.selector_evaluations[i] = batched_lpc_verifier.get_fixed_values_z_i_j_from_proof_be(
                    blob,
                    eval_proof_combined_value_offset,
                    i + ar_params.permutation_columns + ar_params.permutation_columns + ar_params.constant_columns,
                    0
            );
            unchecked{i++;}
        }

        gate_params.constant_evaluations = new uint256[](ar_params.constant_columns);
        for (uint256 i = 0; i < ar_params.constant_columns;) {
            gate_params.constant_evaluations[i] = batched_lpc_verifier.get_fixed_values_z_i_j_from_proof_be(
                    blob,
                    eval_proof_combined_value_offset,
                    i + ar_params.permutation_columns + ar_params.permutation_columns,
                    0
            );
            unchecked{i++;}
        }

        gate_params.theta_acc = 1;
        gate_params.gates_evaluation = 0;

		(gate_params.gates_evaluation, gate_params.theta_acc) = gate0.evaluate_gate_be(gate_params);
		(gate_params.gates_evaluation, gate_params.theta_acc) = gate1.evaluate_gate_be(gate_params);
		(gate_params.gates_evaluation, gate_params.theta_acc) = gate2.evaluate_gate_be(gate_params);
		(gate_params.gates_evaluation, gate_params.theta_acc) = gate3.evaluate_gate_be(gate_params);
		(gate_params.gates_evaluation, gate_params.theta_acc) = gate4.evaluate_gate_be(gate_params);
		(gate_params.gates_evaluation, gate_params.theta_acc) = gate5.evaluate_gate_be(gate_params);
		(gate_params.gates_evaluation, gate_params.theta_acc) = gate6.evaluate_gate_be(gate_params);
		(gate_params.gates_evaluation, gate_params.theta_acc) = gate7.evaluate_gate_be(gate_params);
		(gate_params.gates_evaluation, gate_params.theta_acc) = gate8.evaluate_gate_be(gate_params);
		(gate_params.gates_evaluation, gate_params.theta_acc) = gate9.evaluate_gate_be(gate_params);
		(gate_params.gates_evaluation, gate_params.theta_acc) = gate10.evaluate_gate_be(gate_params);


        gates_evaluation = gate_params.gates_evaluation;
    }
}
