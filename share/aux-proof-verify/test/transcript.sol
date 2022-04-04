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
import '../contracts/cryptography/transcript.sol';
import '../contracts/algebra/bn254.sol';

contract TestTranscript {
    function test_transcript() public {
        bytes memory init_blob = hex"00010203040506070809";
        bytes memory updated_blob = hex"0a0b0c0d0e0f";
        types.transcript_data memory tr_state;
        transcript.init_transcript(tr_state, init_blob);

        Assert.equal(tr_state.current_challenge, hex"f0ae86a6257e615bce8b0fe73794934deda00c13d58f80b466a9354e306c9eb0", "States are not equal");

        uint256[] memory ch_n1 = new uint256[](3);
        uint256 ch1 = transcript.get_field_challenge(tr_state, bn254_crypto.r_mod);
        uint256 ch2 = transcript.get_field_challenge(tr_state, bn254_crypto.r_mod);
        transcript.get_field_challenges(tr_state, ch_n1, bn254_crypto.r_mod);

        uint256[3] memory expected_ch_n1 = [
            2245175900862542509951906212793478103240010197496750948704322685051902675354,
            16320131460301285401920244887277720416842414649440531539775969345471712992772,
            7576039756886122119376570618873144488644512682503555904028346442798478224108
        ];

        Assert.equal(ch1, 410520887291797743055529280205380884898232066603165141341545420025204569828, "Challenges are not equal");
        Assert.equal(ch2, 6957757883002647951325110021322547143346349859370624486517662147347218797451, "Challenges are not equal");
        for (uint256 i = 0; i < ch_n1.length; i++) {
            Assert.equal(ch_n1[i], expected_ch_n1[i], "Challenges are not equal");
        }

        transcript.update_transcript(tr_state, updated_blob);
        uint256[] memory ch_n2 = new uint256[](3);
        transcript.get_field_challenges(tr_state, ch_n2, bn254_crypto.r_mod);

        uint256[3] memory expected_ch_n2 = [
            3901835814944774396760742241791593702879373256387333213493637370872332164712,
            6108247989207264546402917301809084770490371695233206138489890080662345908908,
            19775691949012520084096067137227560009691209393892029746311573958132466580842
        ];

        for (uint256 i = 0; i < ch_n2.length; i++) {
            Assert.equal(ch_n2[i], expected_ch_n2[i], "Challenges are not equal");
        }

        Assert.equal(uint256(4329468119771583341), transcript.get_integral_challenge_be(tr_state, 8), "Challenges are not equal");
    }
}
