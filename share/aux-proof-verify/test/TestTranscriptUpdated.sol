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

pragma solidity >=0.6.0;
pragma experimental ABIEncoderV2;

import "truffle/Assert.sol";
import '../contracts/cryptography/transcript_updated.sol';
import '../contracts/cryptography/bn254.sol';

contract TestTranscript {
    function test_transcript() public {
        bytes memory init_blob = hex"00010203040506070809";
        bytes memory updated_blob = hex"0a0b0c0d0e0f";
        transcript_updated.transcript_data memory tr_state;
        transcript_updated.init_transcript(tr_state, init_blob);
        uint256[] memory ch_n1 = new uint256[](3);
        uint256 ch1 = transcript_updated.get_field_challenge(tr_state, bn254_crypto.r_mod);
        uint256 ch2 = transcript_updated.get_field_challenge(tr_state, bn254_crypto.r_mod);
        transcript_updated.get_field_challenges(tr_state, ch_n1, bn254_crypto.r_mod);

        uint256[3] memory expected_ch_n1 = [
            10670072364229193268345883558806049481482380988897342068103436942097264490775,
            20116560061236635637740174882396539778446103072514228519631816014469713595180,
            1372249526779755214631752009867711889138746351633366492295966156562722086759
        ];

        Assert.equal(ch1, 662226101649256508861335501384346260158109737217244077368209034823388288134, "Challenges are not equal");
        Assert.equal(ch2, 12618297757667089100847824173271171944692736177364121732906933153931760794764, "Challenges are not equal");
        for (uint256 i = 0; i < ch_n1.length; i++) {
            Assert.equal(ch_n1[i], expected_ch_n1[i], "Challenges are not equal");
        }

        transcript_updated.update_transcript(tr_state, updated_blob);
        uint256[] memory ch_n2 = new uint256[](3);
        transcript_updated.get_field_challenges(tr_state, ch_n2, bn254_crypto.r_mod);

        uint256[3] memory expected_ch_n2 = [
            18542202176933893015003292389613565987034174912764010128781565434879825219602,
            3295211654673992481034338207510327059852423977160281182678424298896659513210,
            4494002323459210531936307752898502905847960823617429120379281499930410051361
        ];

        for (uint256 i = 0; i < ch_n2.length; i++) {
            Assert.equal(ch_n2[i], expected_ch_n2[i], "Challenges are not equal");
        }
    }
}
