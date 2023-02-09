//---------------------------------------------------------------------------//
// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Elena Tatuzova <e.tatuzova@nil.foundation>
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

library profiling{
    uint8 constant START_BLOCK_COMMAND_CODE=0;
    uint8 constant END_BLOCK_COMMAND_CODE=1;
    uint8 constant LOG_MESSAGE_CODE=2;
    uint8 constant LOG_DECIMAL_CODE=3;
    uint8 constant LOG_HEXADECIMAL_CODE=4;

    event gas_usage_emit(uint8 command, string function_name, uint256 gas_usage);

    function start_block(string memory function_name) internal {
        emit gas_usage_emit(START_BLOCK_COMMAND_CODE, function_name, gasleft());
    }

    function end_block() internal {
        emit gas_usage_emit(END_BLOCK_COMMAND_CODE, "", gasleft()) ;
    }

    function log_message(string memory message) internal {
        emit gas_usage_emit(LOG_MESSAGE_CODE, message, gasleft()) ;
    }

    function log_dec(string memory description, uint256 num) internal{
        emit gas_usage_emit(LOG_DECIMAL_CODE, description, num);
    }
    
    function log_hex(string memory description, uint256 num) internal{
        emit gas_usage_emit(LOG_HEXADECIMAL_CODE, description, num);
    }
}