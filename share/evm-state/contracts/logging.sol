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

library logging {
    uint8 constant START_BLOCK_COMMAND_CODE=0;
    uint8 constant END_BLOCK_COMMAND_CODE=1;
    uint8 constant LOG_MESSAGE_CODE=2;

    event gas_usage_emit(uint8 command, string function_name, uint256 gas_usage);

    function uint2decstr(uint256 _i)
        internal pure returns (string memory _uintAsString)
    { 
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len;
        while (_i != 0) {
            k = k - 1;
            uint8 temp = (48 + uint8(_i - (_i / 10) * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }

    function uint2hexstr(uint256 i) internal pure returns (string memory) {
        if (i == 0) return "0";
        uint256 j = i;
        uint256 length;
        while (j != 0) {
            length++;
            j = j >> 4;
        }
        uint256 mask = 15;
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        while (i != 0) {
            uint256 curr = (i & mask);
            bstr[--k] = curr > 9
                ? bytes1(uint8(55 + curr))
                : bytes1(uint8(48 + curr)); // 55 = 65 - 10
            i = i >> 4;
        }
        return string(bstr);
    }

    function memory_chunk256_to_hexstr(bytes memory blob, uint256 offset) internal pure returns (string memory){
        uint256 logvar;
        assembly {
            logvar:=mload(add(blob, offset))
        }
        return logging.uint2hexstr(logvar);
    }

    function calldata_chunk256_to_hexstr(bytes calldata blob, uint256 offset) internal pure returns (string memory result){
        uint256 logvar;
        assembly {
            logvar := calldataload(add(blob.offset, offset))
        }
        return logging.uint2hexstr(logvar);
    }
}
