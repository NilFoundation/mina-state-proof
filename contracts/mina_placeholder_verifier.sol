// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2023 Haresh G <hgedia@nil.foundation>
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

import "./protocol/state.sol";
import "./protocol/constants.sol";
import "./interfaces/IMinaPlaceholderVerifier.sol";
import "./state_proof/mina_state_proof.sol";
import "./account_proof/account_proof.sol";

/// TODO - Update event logic/description

/**
 * @dev Interface implementation of IMinaPlaceholderVerifier.
 */
contract MinaPlaceholderVerifier is IMinaPlaceholderVerifier {
    MinaStateProof mina_state_proof;
    AccountPathProof account_proof;
    mapping(bytes32 => bool) validatedLedgers;

    constructor() {
        mina_state_proof = new MinaStateProof();
        account_proof = new AccountPathProof();
    }

    /// @inheritdoc IMinaPlaceholderVerifier
    function isValidatedLedgerHash(string calldata ledger_hash) external view returns (bool) {
        return validatedLedgers[keccak256(bytes(ledger_hash))];
    }

    /// @inheritdoc IMinaPlaceholderVerifier
    function verifyLedgerState(string calldata ledger_hash,
        bytes calldata proof, uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations) external returns (bool) {
        if (!this.isValidatedLedgerHash(ledger_hash))
            if (!mina_state_proof.verify(proof, init_params, columns_rotations, address(this))) {
                emit LedgerProofValidationFailed();
                return false;
            }
        return true;
    }

    /// @inheritdoc IMinaPlaceholderVerifier
    function verifyAccountState(state.account_state calldata account_state, string calldata ledger_hash,
        bytes calldata account_state_proof,
        uint256[][] calldata init_params, int256[][][] calldata columns_rotations
    ) external returns (bool) {
        if (!this.isValidatedLedgerHash(ledger_hash) || !account_proof.verify(account_state_proof, init_params, columns_rotations, address(this))) {
            emit AccountProofValidationFailed();
            return false;
        }
        return true;
    }

    /// @inheritdoc IMinaPlaceholderVerifier
    function updateLedgerProof(string calldata ledger_hash,
        bytes calldata proof, uint256[][] calldata init_params, int256[][][] calldata columns_rotations
    ) external {
        require(this.verifyLedgerState(ledger_hash, proof, init_params, columns_rotations), "Proof validation failed");
        validatedLedgers[keccak256(bytes(ledger_hash))] = true;
        emit LedgerProofValidatedAndUpdated();
    }
}