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
contract MinaState is IMinaPlaceholderVerifier, Ownable {
    MinaStateProof _state_proof;
    AccountPathProof _account_proof;

    mapping(bytes32 => bool) validatedLedgers;

    constructor(address state_proof, address account_proof) {
        _state_proof = MinaStateProof(state_proof);
        _account_proof = AccountPathProof(account_proof);
    }

    function setStateProofVerifier(address state_proof) external onlyOwner {
        _state_proof = MinaStateProof(state_proof);
    }

    /// @inheritdoc IMinaPlaceholderVerifier
    function isValidatedLedgerHash(string calldata ledger_hash) external view returns (bool) {
        return validatedLedgers[keccak256(bytes(ledger_hash))];
    }

    /// @inheritdoc IMinaPlaceholderVerifier
    function verifyLedgerState(string calldata ledger_hash,
        bytes calldata proof, uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations) external returns (bool) {
        if (!this.isValidatedLedgerHash(ledger_hash)) {
            if (!_state_proof.verify(proof, init_params, columns_rotations)) {
                emit LedgerProofValidationFailed();
                return false;
            }
        }
        emit LedgerProofValidated();
        return true;
    }

    /// @inheritdoc IMinaPlaceholderVerifier
    function verifyAccountState(state.account_state_type calldata account_state, string calldata ledger_hash,
        bytes calldata account_state_proof, uint256[] calldata init_params,
        int256[][] calldata columns_rotations) external returns (bool) {
        if (!this.isValidatedLedgerHash(ledger_hash)) {
            emit InvalidLedgerHash();
            emit AccountProofValidationFailed();
            return false;
        }

        require(account_state_proof.length >= 51, "account_state_proof is too short");
        bytes memory ledger_hash_bytes = new bytes(51);
        for(uint i = 0; i < 51; i++) {
            ledger_hash_bytes[i] = account_state_proof[i];
        }
        string memory ledger_hash_from_proof = string(ledger_hash_bytes);
        if (!(keccak256(abi.encodePacked((ledger_hash_from_proof))) == keccak256(abi.encodePacked((ledger_hash))))) {
            emit InvalidLedgerHash();
            emit AccountProofValidationFailed();
            return false;
        }
        bytes memory remaining_proof = new bytes(account_state_proof.length - 51);
        for(uint i = 51; i < account_state_proof.length; i++) {
            remaining_proof[i - 51] = account_state_proof[i];
        }

        if (!_account_proof.verify(remaining_proof, init_params, columns_rotations)) {
            emit AccountProofValidationFailed();
            return false;
        }
        emit AccountProofValidated();
        return true;
    }

    /// @inheritdoc IMinaPlaceholderVerifier
    function updateLedgerProof(string calldata ledger_hash,
        bytes calldata proof,
        uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations) external {
        if (this.verifyLedgerState(
                ledger_hash, proof, init_params, columns_rotations)) {
            validatedLedgers[keccak256(bytes(ledger_hash))] = true;
            emit LedgerProofValidatedAndUpdated();
        }
    }
}