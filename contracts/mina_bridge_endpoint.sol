// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2023 Amit Sagar <asagar@nil.foundation>
// Copyright (c) 2023 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

import "@nilfoundation/evm-placeholder-verification/contracts/logging.sol";
//TODO : Check if can be moved out
//import "@nilfoundation/evm-placeholder-verification/contracts/profiling.sol";

import "./state.sol";
import "./mina.sol";
import "./constants.sol";

import "./state-proof/mina_state_proof.sol";

import "./interfaces/IMinaPlaceholderVerifier.sol";

contract MinaBridgeEndpoint is IMinaPlaceholderVerifier {

    MinaStateProof mina_state_proof;

    // logging.gas_usage_emit events will be thrown too.
    event gas_usage_emit(uint8 command, string function_name, uint256 gas_usage);

    state.protocol s;
    state.commitlog c;
    uint256 ledger_hash;
    string current_ledger_hash;

    function setState(state.protocol memory _s) external {
        s = _s;
    }

    function getState() external returns (uint256) {
        ledger_hash = s.previous_state_hash;
    }

    function verify_ledger_state(string calldata ledger_hash, bytes calldata proof, uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations) external returns (bool) {
            if (keccak256(bytes(current_ledger_hash)) == keccak256(bytes(ledger_hash))) {
                return true;
            }
            require(mina_state_proof.verify(proof, init_params, columns_rotations), "Proof is not correct");
            return true;
    }

    function update_ledger_state(string calldata ledger_hash, bytes calldata proof, uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations) external  {
            require(this.verify_ledger_state(ledger_hash, proof, init_params, columns_rotations), "Proof is not correct");
            current_ledger_hash = ledger_hash;
    }

    function verify_account(string calldata account_hash, bytes calldata proof, bytes calldata account_state) external returns (bool) {
        return true;
    }
}