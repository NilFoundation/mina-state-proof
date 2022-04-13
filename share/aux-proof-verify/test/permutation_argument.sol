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
import '../contracts/types.sol';
import '../contracts/redshift/permutation_argument.sol';

contract TestPermutationArgumentNative {
    function test_permutation_argument_case1() public {
        bytes memory column_polynomials_values_blob = hex"001d0d9000e771e5edffc0967538476fe1923714ecef65978b03723a0eb0041a0d9e22e67169ff5d2ce8c7fce296b6fb8ac88b90af108129955f7d4ab9a15ae92fb4370d95733c95f13b11237ff687e8f8252755d24c08cb7f5ad9a1f6834feb26e650fbed8d2b31dde8ad96f99739165b2d88f1d26db0f02bb9d1373c1b63cf21f685eb93c6c97414699a55ac4d0ce7995a82fc1a00fc0d6b7a096f5bc6546a3a9d57b467f18ba615ce72124773115a428c07f13c42a64adb5c33be78ddcdc4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ad5f06882335b436a2dc307d121911caac81929e9e8aa194d108a516f2db8e7000000000000000000000000000000000000000000000000000000000000000034eac3845fee743e5e5d7f855c2bafe95d43bae3f77622491d90888798b865790000000000000000000000000000000000000000000000000000000000000000";
        bytes memory S_id_blob = hex"098b0fb643885f65cec7b0f4a20d9a57a81595f196d1bda8675e33b31cc7c5bd2fb74e8f51a9dcfd09e674c72a4403b6486bedb7f218b44a04d7027f8fe6dcb12e9488cc985150f1318047e3d354128f0347d9a39e949a1f4cab79b6cf824f7228e6abfef99694b5f781677320a45ccaa993753dfd001749b3d1cdcb0d8b8d370c815bfadff0e78dd587053fa335cff4e90d7f41d519891db791723043b9c2103e86cbe65fb485c52ba31a3e300d0fc88d437c49297fad9495d73af152a0ca5038a1fb7fde869cd9da2f8336f0414eea3937097daa4a7f78887f63029d23f38c1b29e97f58a1104142ed9012b1468a9294f8cb842e4098ec45c82b5911b3c1b807d18f7cbb2551464ea3d05d7660b4dca44ec79cd4a90a662a8e76e35882c8962717cd6fa7ba965f893311d34fe3884f3589e610274d33fed4c85270ba8deaee0377032e46a4efddadff59208f71a98ba4ddb35ca89b18a75c62096ca4c596a311530fe76138af5465fcbda2cd384fba385480cf4b077b44cdea2f1f37dbf12f";
        bytes memory S_sigma_blob = hex"098b0fb643885f65cec7b0f4a20d9a57a81595f196d1bda8675e33b31cc7c5bd2fb74e8f51a9dcfd09e674c72a4403b6486bedb7f218b44a04d7027f8fe6dcb12e9488cc985150f1318047e3d354128f0347d9a39e949a1f4cab79b6cf824f7228e6abfef99694b5f781677320a45ccaa993753dfd001749b3d1cdcb0d8b8d370c815bfadff0e78dd587053fa335cff4e90d7f41d519891db791723043b9c2103e86cbe65fb485c52ba31a3e300d0fc88d437c49297fad9495d73af152a0ca503fa95b678a542f0151b2f4e6557b7cb0d3206149f2364ab2610bc19c321493561b29e97f58a1104142ed9012b1468a9294f8cb842e4098ec45c82b5911b3c1b807d18f7cbb2551464ea3d05d7660b4dca44ec79cd4a90a662a8e76e35882c8962717cd6fa7ba965f893311d34fe3884f3589e610274d33fed4c85270ba8deaee0377032e46a4efddadff59208f71a98ba4ddb35ca89b18a75c62096ca4c596a30a4bafffb56b1d2cee794bf367fe21f39e6b2903031bb00af55dd085a2eb5165";
        types.permutation_argument_eval_params memory params;
        params.modulus = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001;
        params.challenge = 4316515819271112191959214260307160487355688632151288401666493702985746990525;
        params.beta = 8913152039927370867864620503109900648147403988631835618521844699477017082188;
        params.gamma = 2316782803766550451829621736806564756314854148191492421914303696403522278610;
        params.perm_polynomial_value = 1;
        params.perm_polynomial_shifted_value = 1;
        params.q_last_eval = 13999826423747567137123496940434711920412742386286813791218855552927143290328;
        params.q_blind_eval = 19370296004945959788133544749639859787788107681683555575106426224754701333537;
        params.column_polynomials_values = new uint256[](12);
        params.id_permutation_ptrs = new uint256[](12);
        params.sigma_permutation_ptrs = new uint256[](12);
        assembly {
            let column_polynomials_values_blob_ptr := add(column_polynomials_values_blob, 0x20)
            let column_polynomials_values_ptrs_ptr := add(mload(add(params, 0x40)), 0x20)

            let S_id_blob_ptr := add(S_id_blob, 0x20)
            let id_permutation_ptrs_ptr := add(mload(add(params, 0x60)), 0x20)

            let S_sigma_blob_ptr := add(S_sigma_blob, 0x20)
            let sigma_permutation_ptrs_ptr := add(mload(add(params, 0x80)), 0x20)
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                mstore(column_polynomials_values_ptrs_ptr, mload(column_polynomials_values_blob_ptr))
                column_polynomials_values_blob_ptr := add(column_polynomials_values_blob_ptr, 0x20)
                column_polynomials_values_ptrs_ptr := add(column_polynomials_values_ptrs_ptr, 0x20)

                mstore(id_permutation_ptrs_ptr, S_id_blob_ptr)
                S_id_blob_ptr := add(S_id_blob_ptr, 0x20)
                id_permutation_ptrs_ptr := add(id_permutation_ptrs_ptr, 0x20)

                mstore(sigma_permutation_ptrs_ptr, S_sigma_blob_ptr)
                S_sigma_blob_ptr := add(S_sigma_blob_ptr, 0x20)
                sigma_permutation_ptrs_ptr := add(sigma_permutation_ptrs_ptr, 0x20)
            }
        }

        uint256[] memory F_result = new uint256[](3);
        F_result[0] = 0;
        F_result[1] = 1230429689271326281245028718172049222371625439522538298410105267101982198912;
        F_result[2] = 0;

        uint256[] memory F = permutation_argument.verify_eval_be(params);
        Assert.equal(F_result[0], F[0], "F[0] is not correct");
        Assert.equal(F_result[1], F[1], "F[1] is not correct");
        Assert.equal(F_result[2], F[2], "F[2] is not correct");
        Assert.equal(F_result, F, "F is not correct");
    }

    function test_permutation_argument_case2() public {
        bytes memory column_polynomials_values_blob = hex"3e33f96959ec3e4773cb8a65e7b84ec0d939e047cd0888ea2051a6f65f01b3d9148cd6288be080277e873b84d70ba858464a24058161795d5145e8fdf38edc3108210e7a0924d62141bca75267ace1a167572afe69be806e8c9021318a15dd17193e75723a023af75754573f9d9c7654fc5271b215b162ad240dff632967b9b40c208381294c11071d9ace5df534f52f5a15e8a6d4cd6c14d4da70111da5d1db060dbdcf1754d2ebe88a8935edbb730bb3903112a3a1c1b44786fb478abbdaf5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c8d33189732c852b67d20f95199d96c563fdd5bb8eaafb63608687507da922b00000000000000000000000000000000000000000000000000000000000000002eb803bf263967fda991f9b17eec775c69de0974328351a6b84bdbe25727316a0000000000000000000000000000000000000000000000000000000000000000";
        bytes memory S_id_blob = hex"1e3ede9b87e3c0a250ac546b5c8bee9d8efd753a5753139cef74eb82d5142457173a5909a772c32b935da618cebba9138666182ba2056fd97aee37b42964b5b13423bd30453dcfd9e0d43e7c09aa4d617db7dfde20ce3623cd79e597cef78c7404b2b1f15a350f416425386c305382e6eb7cfb667ed32a449eacb8430ad5be40177d79b6c3094c46f4ba1a1cf1a18e829970e9007a1fd357195f994f362cb74035736091cf2e7d62c7a28290b827c88cdcedf40659522797e5b0cd9f0edf943f0b40e2d90be872ede62c8cd398c6eabfc78b602f9966e18917bf40674a5de53738446e3d3b8a3ea57edec021fbe295bee5b8e0edff0267ad76bc420473d57a131956273229b3393b7a59c0a9eb6cecb9f38200b5d5d821f4ecf88662432b625b3eaec3fad0801e2963c0c35199209fa19f436a9123ebb0ad07ad6efe4fd8ebc63969d3e6128096cef2c3d097fda31e279336b0e58e668ef2c1ae67438f3c9ada1f11237e5c82f20abdd312f7f42f96c556f7108ba2cce64f63b3409dcc2f063e";
        bytes memory S_sigma_blob = hex"1e3ede9b87e3c0a250ac546b5c8bee9d8efd753a5753139cef74eb82d5142457173a5909a772c32b935da618cebba9138666182ba2056fd97aee37b42964b5b13423bd30453dcfd9e0d43e7c09aa4d617db7dfde20ce3623cd79e597cef78c7404b2b1f15a350f416425386c305382e6eb7cfb667ed32a449eacb8430ad5be40177d79b6c3094c46f4ba1a1cf1a18e829970e9007a1fd357195f994f362cb74035736091cf2e7d62c7a28290b827c88cdcedf40659522797e5b0cd9f0edf943f0168fdde811a55aa199d168a4b6e4889f0543a7338518eca59a25fa78bb503c638446e3d3b8a3ea57edec021fbe295bee5b8e0edff0267ad76bc420473d57a131956273229b3393b7a59c0a9eb6cecb9f38200b5d5d821f4ecf88662432b625b3eaec3fad0801e2963c0c35199209fa19f436a9123ebb0ad07ad6efe4fd8ebc63969d3e6128096cef2c3d097fda31e279336b0e58e668ef2c1ae67438f3c9ada28e90878e7510f4e8a628941418838fb2e2e364803e2390e21d0215d8ad7e7af";
        types.permutation_argument_eval_params memory params;
        params.modulus = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001;
        params.challenge = 13680466356305823703000145650239733316660673444300695924302637406762841678935;
        params.beta = 14719233839400035676220323197626899693305040335922105351507119010167282393124;
        params.gamma = 15737342172854684283519564826832975114229566743888410049807169101804738146358;
        params.perm_polynomial_value = 1;
        params.perm_polynomial_shifted_value = 1;
        params.q_last_eval = 1003188330204223361284696557335529039690738119140782086203806503030447081647;
        params.q_blind_eval = 1068012289539091434797183909362029488296752803983909452234101517389351617211;
        params.column_polynomials_values = new uint256[](12);
        params.id_permutation_ptrs = new uint256[](12);
        params.sigma_permutation_ptrs = new uint256[](12);
        assembly {
            let column_polynomials_values_blob_ptr := add(column_polynomials_values_blob, 0x20)
            let column_polynomials_values_ptrs_ptr := add(mload(add(params, 0x40)), 0x20)

            let S_id_blob_ptr := add(S_id_blob, 0x20)
            let id_permutation_ptrs_ptr := add(mload(add(params, 0x60)), 0x20)

            let S_sigma_blob_ptr := add(S_sigma_blob, 0x20)
            let sigma_permutation_ptrs_ptr := add(mload(add(params, 0x80)), 0x20)
            for { let i := 0 } lt(i, 12) { i := add(i, 1) } {
                mstore(column_polynomials_values_ptrs_ptr, mload(column_polynomials_values_blob_ptr))
                column_polynomials_values_blob_ptr := add(column_polynomials_values_blob_ptr, 0x20)
                column_polynomials_values_ptrs_ptr := add(column_polynomials_values_ptrs_ptr, 0x20)

                mstore(id_permutation_ptrs_ptr, S_id_blob_ptr)
                S_id_blob_ptr := add(S_id_blob_ptr, 0x20)
                id_permutation_ptrs_ptr := add(id_permutation_ptrs_ptr, 0x20)

                mstore(sigma_permutation_ptrs_ptr, S_sigma_blob_ptr)
                S_sigma_blob_ptr := add(S_sigma_blob_ptr, 0x20)
                sigma_permutation_ptrs_ptr := add(sigma_permutation_ptrs_ptr, 0x20)
            }
        }

        uint256[] memory F_result = new uint256[](3);
        F_result[0] = 0;
        F_result[1] = 15171506756509873248241781534696835201786556302235417496068058824863621386170;
        F_result[2] = 0;

        uint256[] memory F = permutation_argument.verify_eval_be(params);
        Assert.equal(F_result[0], F[0], "F[0] is not correct");
        Assert.equal(F_result[1], F[1], "F[1] is not correct");
        Assert.equal(F_result[2], F[2], "F[2] is not correct");
        Assert.equal(F_result, F, "F is not correct");
    }
}
