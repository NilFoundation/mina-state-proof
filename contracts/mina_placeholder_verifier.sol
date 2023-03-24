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

import "./state.sol";
import "./mina.sol";
import "./constants.sol";
import "./state-proof/mina_state_proof.sol";
import "./interfaces/IMinaPlaceholderVerifier.sol";

contract MinaPlaceholderVerifier is IMinaPlaceholderVerifier {
    MinaStateProof mina_state_proof;
    mapping(bytes32=>bool) validatedLedgers;

    constructor(){
        mina_state_proof = new MinaStateProof();
    }


    function is_validated_ledger_hash(string calldata ledger_hash) external view returns (bool) {
        return validatedLedgers[keccak256(bytes(ledger_hash))];
    }


    function verify_ledger_state(string calldata ledger_hash,
        bytes calldata proof, uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations) external returns (bool) {
            if(!this.is_validated_ledger_hash(ledger_hash))
                return mina_state_proof.verify(proof, init_params, columns_rotations);
            return true;
    }

    function verify_account_state(state.account_state calldata account_state,string calldata ledger_hash ,
        bytes calldata account_state_proof,
        uint256[][] calldata init_params, int256[][][] calldata columns_rotations
        ) external returns (bool){
        return this.is_validated_ledger_hash(ledger_hash);
    }

    function update_ledger_proof(string calldata ledger_hash,
        bytes calldata proof, uint256[][] calldata init_params,int256[][][] calldata columns_rotations
        ) external  {
            require(this.verify_ledger_state(ledger_hash, proof, init_params, columns_rotations), "Proof is not correct");
            validatedLedgers[keccak256(bytes(ledger_hash))] = true;
    }
}