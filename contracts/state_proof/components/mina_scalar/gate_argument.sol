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
import "@nilfoundation/evm-placeholder-verification/contracts/interfaces/gate_argument.sol";

import "./gate0.sol";
import "./gate3.sol";
import "./gate8.sol";
import "./gate10.sol";
import "./gate12.sol";
import "./gate14.sol";
import "./gate16.sol";
import "./gate18.sol";
import "./gate22.sol";

// TODO: name component
contract mina_scalar_split_gen is IGateArgument{
    // TODO: specify constants
    uint256 constant GATES_N = 24;

    // circuit-specific gate argument local variables type
    struct local_vars_type {
        // 0x0
        uint256 constraint_eval;
        // 0x20
        uint256 gate_eval;
        // 0x40
        uint256 gates_evaluation;
        // 0x60
        uint256 theta_acc;
        // 0x80
        uint256[][] witness_evaluations;
        // 0xa0
        uint256[] constant_evaluations;
        // 0xc0
        uint256[] selector_evaluations;
    }

    // TODO: columns_rotations could be hard-coded
    function evaluate_gates_be(
        bytes calldata blob,
        uint256 eval_proof_combined_value_offset,
        types.gate_argument_params memory gate_params,
        types.arithmetization_params memory ar_params,
        int256[][] calldata columns_rotations
    ) external pure returns (uint256 gates_evaluation) {
        local_vars_type memory local_vars;

        local_vars.witness_evaluations = new uint256[][](ar_params.witness_columns);
        for (uint256 i = 0; i < ar_params.witness_columns;) {
            local_vars.witness_evaluations[i] = new uint256[](columns_rotations[i].length);
            for (uint256 j = 0; j < columns_rotations[i].length;) {
                local_vars.witness_evaluations[i][j] = batched_lpc_verifier.get_variable_values_z_i_j_from_proof_be(
                    blob, eval_proof_combined_value_offset, i, j
                );
                unchecked{j++;}
            }
            unchecked{i++;}
        }

        local_vars.selector_evaluations = new uint256[](GATES_N);
        for (uint256 i = 0; i < GATES_N;) {
            local_vars.selector_evaluations[i] = batched_lpc_verifier.get_fixed_values_z_i_j_from_proof_be(
                    blob,
                    eval_proof_combined_value_offset,
                    i + ar_params.permutation_columns + ar_params.permutation_columns + ar_params.constant_columns,
                    0
            );
            unchecked{i++;}
        }

        local_vars.constant_evaluations = new uint256[](ar_params.constant_columns);
        for (uint256 i = 0; i < ar_params.constant_columns;) {
            local_vars.constant_evaluations[i] = batched_lpc_verifier.get_fixed_values_z_i_j_from_proof_be(
                    blob,
                    eval_proof_combined_value_offset,
                    i + ar_params.permutation_columns + ar_params.permutation_columns,
                    0
            );
            unchecked{i++;}
        }

        local_vars.theta_acc = 1;
        local_vars.gates_evaluation = 0;
        (local_vars.gates_evaluation, local_vars.theta_acc) = mina_scalar_gate0.evaluate_gate_be(gate_params, local_vars);
        (local_vars.gates_evaluation, local_vars.theta_acc) = mina_scalar_gate3.evaluate_gate_be(gate_params, local_vars);
        (local_vars.gates_evaluation, local_vars.theta_acc) = mina_scalar_gate8.evaluate_gate_be(gate_params, local_vars);
        (local_vars.gates_evaluation, local_vars.theta_acc) = mina_scalar_gate10.evaluate_gate_be(gate_params, local_vars);
        (local_vars.gates_evaluation, local_vars.theta_acc) = mina_scalar_gate12.evaluate_gate_be(gate_params, local_vars);
        (local_vars.gates_evaluation, local_vars.theta_acc) = mina_scalar_gate14.evaluate_gate_be(gate_params, local_vars);
        (local_vars.gates_evaluation, local_vars.theta_acc) = mina_scalar_gate16.evaluate_gate_be(gate_params,local_vars);
        (local_vars.gates_evaluation, local_vars.theta_acc) = mina_scalar_gate18.evaluate_gate_be(gate_params,local_vars);
        (local_vars.gates_evaluation, local_vars.theta_acc) = mina_scalar_gate22.evaluate_gate_be(gate_params,local_vars);
        gates_evaluation = local_vars.gates_evaluation;
    }
}
