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

import "../state.sol";

interface IMinaPlaceholderVerifier {

    function setState(state.protocol memory _s) external;

    function getState() external returns (uint256);

    function verify_ledger_state(string calldata ledger_hash, bytes calldata proof, uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations) external returns (bool);

    function update_ledger_state(string calldata ledger_hash, bytes calldata proof, uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations) external;

    function verify_account(string calldata account_hash, bytes calldata proof, bytes calldata account_state) external returns (bool);

}