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

import "truffle/Assert.sol";
import '../contracts/algebra/field.sol';
import '../contracts/cryptography/transcript.sol';
import '../contracts/algebra/bn254.sol';

contract TestOperationsPerformance {
    function test_transcript_get_field_challenge() public {
        bytes memory init_blob = hex"00010203040506070809";
        types.transcript_data memory tr_state;
        transcript.init_transcript(tr_state, init_blob);
        transcript.get_field_challenge(tr_state, bn254_crypto.r_mod);
    }

    function test_transcript_get_field_challenges_10() public {
        bytes memory init_blob = hex"00010203040506070809";
        types.transcript_data memory tr_state;
        transcript.init_transcript(tr_state, init_blob);
        uint256[] memory ch_n1 = new uint256[](10);
        transcript.get_field_challenges(tr_state, ch_n1, bn254_crypto.r_mod);
    }

    function test_transcript_get_integral_challenge_be_8_bytes() public {
        bytes memory init_blob = hex"00010203040506070809";
        types.transcript_data memory tr_state;
        transcript.init_transcript(tr_state, init_blob);
        transcript.get_integral_challenge_be(tr_state, 8);
    }

    function test_field_math_log2() public {
        uint256 i = 908723247892348972132478978923429087;
        field.log2(i);
    }

    function test_field_math_expmod_static() public {
        uint256 val = 10359452186428527605436343203440067497552205259388878191021578220384701716497;
        uint256 e = 14940766826517323942636479241147756311199852622225275649687664389641784935947;
        field.expmod_static(val, e, bn254_crypto.r_mod);
    }

    function test_field_math_expmod() public {
        uint256 val = 10359452186428527605436343203440067497552205259388878191021578220384701716497;
        uint256 e = 14940766826517323942636479241147756311199852622225275649687664389641784935947;
        field.pow_small(val, e, bn254_crypto.r_mod);
    }

    function test_field_math_inverse_static() public {
        uint256 val = 10359452186428527605436343203440067497552205259388878191021578220384701716497;
        field.inverse_static(val, bn254_crypto.r_mod);
    }

    function test_field_math_inverse() public {
        uint256 val = 10359452186428527605436343203440067497552205259388878191021578220384701716497;
        field.invmod(val, bn254_crypto.r_mod);
    }
}
