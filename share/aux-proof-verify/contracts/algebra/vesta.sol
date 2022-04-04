// SPDX-License-Identifier: MIT OR Apache-2.0
//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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
pragma experimental ABIEncoderV2;

import {types} from "../types.sol";

/**
 * @title Vesta elliptic curve crypto
 */
library vesta_crypto {
    uint256 constant p_mod = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001;
    uint256 constant r_mod = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001;
}