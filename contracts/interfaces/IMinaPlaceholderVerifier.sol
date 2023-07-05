// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2023 Haresh G <hgedia@nil.foundation>
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

import "../protocol/state.sol";

// TODO - Check if functions verify_ledger_state/verify_account_state can be changed to view

/**
 * @dev Interface class to verify MINA ledger state proof (full ledger) and account
 * state proofs (user balance/zkApp state)
   */
interface IMinaPlaceholderVerifier {

    /**
    * @dev Emitted when Ledger proof validation is successful
   */
    event LedgerProofValidated();
    /**
    * @dev Emitted when Ledger proof validation fails
   */
    event LedgerProofValidationFailed();

   /**
     * @dev Emitted when Account (user balance/zkApp state) proof validation fails
    */
    event AccountProofValidationFailed();

    /**
    * @dev Emitted when Account (user balance/zkApp state) proof validation succeeds
    */
    event AccountProofValidated();


    /**
     * @dev Emitted when an account proof validation is attempted against a ledger has not previously
     * validated.
     */
    event InvalidLedgerHash();

    /**
     * @dev Emitted when ledger proof is successfully validated and stored.
     */
    event LedgerProofValidatedAndUpdated();

    /**
     * @dev Emitted when ledger proof is successfully validated and stored.
     * @param ledger_hash The ledger hash to check if it was validated previously.
     * @return Boolean true is hash was validated and stored previously, false otherwise.
     */
    function isValidatedLedgerHash(string calldata ledger_hash) external view returns (bool);

    /**
     * @dev Validates ledger proof
     * @param ledger_hash The ledger hash.
     * @param proof Ledger proof retrieved from proof market
     * @param init_params - to remove
     * @param columns_rotations - to remove
     * @return Boolean true if ledger hash/proof is passes placeholder proof validation , false otherwise.
     */
    function verifyLedgerState(string calldata ledger_hash, bytes calldata proof, uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations) external returns (bool);

    /**
     * @dev Validates account state proof
     * @param account_state Account structure which has account data
     * @param ledger_hash The ledger hash.
     * @param account_state_proof Account state proof retrieved from proof market
     * @param init_params - to remove
     * @param columns_rotations - to remove
     * @return Boolean true if account hash/proof is passes placeholder proof validation , false otherwise.
     */
    function verifyAccountState(state.account_state calldata account_state,
        string calldata ledger_hash, bytes calldata account_state_proof,
        uint256[] calldata init_params, int256[][] calldata columns_rotations
    ) external returns (bool);

    /**
     * @dev Validates and updates valid ledger proof
     * @param ledger_hash The ledger hash.
     * @param proof Ledger proof retrieved from proof market
     * @param init_params - to remove
     * @param columns_rotations - to remove
     */
    function updateLedgerProof(
        string calldata ledger_hash, 
        bytes calldata proof, 
        uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations) external;
}