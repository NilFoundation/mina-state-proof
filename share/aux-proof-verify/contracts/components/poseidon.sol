// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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
pragma solidity >=0.8.5;

import "../types.sol";

library poseidon_component {
    uint256 constant WITNESSES_N = 15;
    // rotations considered
    uint256 constant WITNESS_ASSIGNMENTS_N = 18;
    uint256 constant GATES_N = 11;
    uint256 constant SBOX = 7;

    /**
     * Assignments offsets
     */
    uint32 constant W0_rot0 = 0x20;
    uint32 constant W0_rot1 = 0x40;
    uint32 constant W1_rot0 = 0x60;
    uint32 constant W1_rot1 = 0x80;
    uint32 constant W2_rot0 = 0xa0;
    uint32 constant W2_rot1 = 0xc0;
    uint32 constant W3_rot0 = 0xe0;
    uint32 constant W4_rot0 = 0x100;
    uint32 constant W5_rot0 = 0x120;
    uint32 constant W6_rot0 = 0x140;
    uint32 constant W7_rot0 = 0x160;
    uint32 constant W8_rot0 = 0x180;
    uint32 constant W9_rot0 = 0x1a0;
    uint32 constant W10_rot0 = 0x1c0;
    uint32 constant W11_rot0 = 0x1e0;
    uint32 constant W12_rot0 = 0x200;
    uint32 constant W13_rot0 = 0x220;
    uint32 constant W14_rot0 = 0x240;

    function get_rotation(uint256 W_idx, uint256 rotation_idx)
        internal
        pure
        returns (int256 rotation)
    {
        if (W_idx >= 0 && W_idx < 3) {
            if (rotation_idx == 0) {
                return 0;
            } else if (rotation_idx == 1) {
                return 1;
            } else {
                require(false);
            }
        } else if (W_idx >= 3 && W_idx < 15) {
            if (rotation_idx == 0) {
                return 0;
            } else {
                require(false);
            }
        } else {
            require(false);
        }
    }

    function evaluate_gates_be(
        uint256[] memory assignment_pointers,
        types.gate_eval_params memory params
    ) internal pure returns (uint256 gates_evaluation) {
        require(assignment_pointers.length >= WITNESS_ASSIGNMENTS_N);
        require(params.selector_evaluations_ptrs.length >= GATES_N);

        // TODO: move definitions as constants to library level (when compiler support will be added)
        params
            .mds = hex"1a9bd250757e29ef4959b9bef59b4e60e20a56307d6491e7b7ea1fac679c7903384aa09faf3a48737e2d64f6a030aa242e6d5d455ae4a13696b48a7320c506cd3d2b7b0209bc3080064d5ce4a7a03653f8346506bfa6d076061217be9e6cfed509ee57c70bc351220b107983afcfabbea79868a4a8a5913e24b7aaf3b4bf3a4220989996bc29a96d17684d3ad4c859813115267f35225d7e1e9a5b5436a2458f14e39adb2e171ae232116419ee7f26d9191edde8a5632298347cdb74c3b2e69d174544357b687f65a9590c1df621818b5452d5d441597a94357f112316ef67cb3ca9263dc1a19d17cfbf15b0166bb25f95dffc53212db207fcee35f02c2c41373cf1fbef75d4ab63b7a812f80b7b0373b2dc21d269ba7c4c4d6581d50aae114c";
        params
            .round_constants = hex"2ec559cd1a1f2f6889fc8ae5f07757f202b364429677c8ff6603fd6d93659b472553b08c788551bfe064d91c17eb1edb8662283229757711b2b30895f0aa3bad25a706fb0f35b260b6f28d61e082d36a8f161be1f4d9416371a7b65f2bfafe4e37c0281fda664cc2448d0e7dd77aaa04752250817a945abeea8cfaaf3ee39ba0140488321291998b8582eaceeb3fa9ca3980eb64a453573c5aaa2910405936b63a73fe35b1bdd66b809aad5eab47b5c83b0146fd7fc632dfb49cd91ae116937821b7c2b35fd7710b06245711f26c0635d3e21de4db10dd3a7369f59f468d7be61803a068d25fef2ef652c8a4847aa18a29d1885e7bf77fd6a34d66536d09cad7291de61c5e6268213772cf7e03c80c2e833eb77c58c46548d158a70fbbd9724b230043a0dc2dfab63607cbe1b9c482fdd937fdefecc6905aa5012e89babead13218af77a05c502d3fa3144efcf47a0f2a0292498c10c6e2368565674e78764f4223e2d94c177d27e071d55729d13a9b216955c7102cc9a95ea40058efb5061172a18257c15ad9b6fe8b7c5ad2129394e902c3c3802e738f24ce2f585ae5f6a380a6f7ba75f216403d2e4940469d199474a65aa5ef814e36400bddef06158dcf8169be41c6227956efef5b4cdde65d00d5e04fe766178bdc731615c6e5b93e31e2e28f50a9a55d2e91774083072734544417e290a1cfebc01801b94d0728fe6630fdedf8da8654a22831040cfc74432464b173ee68628fd90498480b9902f2819046a3ed9863d2d739dd8bc9e90a746fda1197162d0a0bec3db1f2f6042cf04e2219e08b460c305b428670bacab86ac1e9458075778d35c3619ae7ba1f9b2ed7638bb36a12ebcec4d4e8728eb43e3f12a6e33b1ffa1463379018d4e12424e62ca1e9aa3fe25d116ccfbd6a8fccdae0aa9bc164a03ab7e951704ee9a715fbedee6030f33ed70da4c2bfb844ff1a7558b817d1ec300da86a1694f2db45047d5f18b0282b04137350495ab417cf2c47389bf681c39f6c22d9e370b7af75cbcbe4bb109b1528dea2eb5bd96905b88ff05fdf3e0f220fe1d93d1b54953ac98fec825f030083dbbb5eab39311c7a8bfd5e55567fa864b3468b5f9200e529cda03d9ef71017eace73cf67c6112239cbf51dec0e714ee4e5a91dbc9209dc17bbea5bcd09437af1de8f5475ba165b90f8d568683d54e215df97e9287943370cf411842809716ff7592836a45340ec6f2b0f122736d03f0bcb84012f922a4baa73ea0e66f511a5985d4b359d03de60b2edabb1853f476915febc0e40f83a2d1d0084efc3fd9255a9d4beb9b5ea18ab9782b1abb267fc5b773b98ab655fd4d469698e1e1f97534a8d9f45200a9ac28021712be81e905967bac580a0b9ee57bc4231f5ecb936a0979556cb3edcbe4f33edd2094f1443b4b4ec6c457b0425b8463e788b9a2dcda2a4d028c09ad39c30666b78b45cfadd5279f6239379c689a727f6266792726540c31b68f6850b3bd71fe4e89984e2c87415523fb54f24ec8ae71430370154b331a27ca0b953d3dba6b8e01cf07d76c611a211d139f2dff5ac023ed2454f2ed90109ae97c25d60242b86d7169196d2212f268b952dfd95a3937916b99053031803698c932f2a16f7bb9abac089ec2de79c9965881708878683caf53caa83ad9c43c7e25e0ac8fba3dc1360f8a9a9fa0be0e031c8c76a93497b7cac7ed32ade6c02fc5023c5e4aed5aa7dfca0f5492f1b6efab3099360ec960237512f48c858a792c124735f3f924546fb4fdfa2a018e03f53063d3a2e87fd285ba8d647eda676512c875c9b79591acf9033f8b6c1e357126c44b23f3486fbee0d98340a33822513cda935e895857d39a7db8476aeda5a5131cb165a353073fd3e473fd8855528d218eb756fa5f1df9f1eb922ef80b0852588779a7368e3d010def1512815d875923bcf1032957015ef171fbb4329bca0c57d59885522f25f4b082a3cf301cfbc617474c3b6a9bc1057df64b9e4d62badbc7f3867b3dd757c71c1f656205d7bceb019826c0ee22972deb41745d3bd412c2ae3d4c18535f4b60c9e870edffa3d55030bcb17dfd622c46f3275f698319b68d8816bed0368ded435ed61992bc43efa93bd816c214c66410229cfbd1f4a3a42e6a0f82f3c0d49b09bc7b4c042ff2c94b08943ec01d9fb9f43c840757738979b146c3b6d1982280e92a52e8d045633ea12670bf8c01822e31c70976269d89ed58bc79ad2f9d1e3145df890bf898b57e470dd53b41599ae78dbd3e689b65ebcca493effa94ed765eeec75a0d3bb20407f9068177d293585e0b8c8e76a8a565c8689a1d88e6a9afa79220bb0a2253f203c335216f471043866edc324ad8d8cf0cc792fe7a10bf874b1eeac67b451d6b2cf51fd6efb2536bfe11ec3736e7f7448c01eb2a5a9041bbf84631cc83ee0464f6af2c982c7352102289fc1b48dafcd9e3cc364d5a4324575e4721daf0af10033c67352f7e8c7662d86db9c722d4d07778858771b832af5bb5dc3b13cf94851c1b4518e3c0c1caa5e3ed66ee1ab6f55a5c8063d8c9b034ae47db43435147149e37d53124b12deb37dcbb3d96c1a08d507523e30e03e0919559bf2daaab238422eade143bf0def31437eb21095200d2d406e6e5727833683d9740b9bfc1713215dc9a1ebee92143f32b4f9d9a90ad62b8483c977480767b53c71f6bde934a8ef38f170ff6c794ad1afaa494088d5f8ee6c47bf9e83013478628cf9f41f2e81383ebeb3d0a10ac3ee707c62e8bdf2cdb49ac2cf4096cf41a7f214fdd1f8f9a24804f171d61014cd3ef0d87d037c56bdfa370a73352b95d472ead1937bed06a31801c91123e185b2ec7f072507ac1e4e743589bb25c8fdb468e329e7de169875f90c52530b780c0c1cb0609623732824c75017da9799bdc7e08b527bae7f409ebdbecf21dfb3801b7ae4e209f68195612965c6e37a2ed5cf1eeee3d46edf655d6f5afef2fdee42805b2774064e963c741552556019a9611928dda728b78311e1f04952831b2b65c431212ed36fdda5358d90cd9cb51c9f493bff71cdc75654547e4a22b1e3ca033d8413b688db7a543e62ac2e69644c0614801379cfe62fa220319e0ef0c8ef1168425028c52a32d93f9313153e52e9cf15e5ec2b4ca09d01730dad432378c73373a36a5ed94a34f75e5de7a7a6187ea301380ecfb6f1a22cf8552638e3218aeec20048a564015e8f221657fbe489ba404d7f5f15b829c7a75a85c2f443312ef7cbbad31430f20f30931b070379c77119c1825c6560cd2c82cf767794e356449a71383674c607fa31ded8c0c0d2d20fb45c36698d258cecd982dba478c0cc88d1c91481d5321174e55b49b2485682c87fac2adb332167a20bcb57db3591defccbd33740803ad284bc48ab959f349b94e18d773c6c0c58a4b9390cc300f2d263cc2e9af126d768d9e1d2bf2cbf32063be831cb1548ffd716bc3ee7034fe111e314db6fb1a28e241028ce3d347c52558a33b6b11285a97fffa1b479e969d027409401e92001d434cba2868e9e371703199c2372d23ef329e537b513f453e24a852bdf9cb2a8fedd5e85a59867d4916b8a57bdd5f84e1047d410770ffffa0205d1b0ee359f621845ac64ff7e383a3eb81e03d2a2966557746d21b47329d6e25c327e2cc93ec6f0f23b5e41c931bfbbe4c12da7d55a2b1c91c79db982df90339df3e22d22b09b4265da50ef175909ce79e8f0b9599dff01cf80e70884982b909b08d58853d8ac908c5b14e5eb8611b45f40faaa59cb8dff98fb30efcdfaa011ece62374d79e717db4a68f9cddaaf52f8884f397375c0f3c5c1dbaa9c57a0a63bd089b727a0ee08e263fa5e35b618db87d7bcce03441475e3fd49639b9fa1c13fedea75f37ad9cfc94c95141bfb4719ee9b32b874b93dcfc0cc12f51a7b2aff36dfa18a9ba1b194228494a8acaf0668cb43aca9d4e0a251b20ec3424d0e65cd119e98db3f49cd7fcb3b0632567d9ccaa5498b0d411a1437f57c658f41931d0c1100b21c306475d816b3efcd75c3ae135c54ad3cc56ca22abd9b7f45e6d02c1915791f9bbea213937208c82794eb667f157f003c65b64aa9800f4bbee4ea51191adbeb5e9c4d515ecfd250ebee56a2a816eb3e3dc8d5d440c1ab4285b350be641fbf4738844a9a249aec253e8e4260e4ab09e26bea29ab0020bf0e813ceecbc33418a929556ec51a086459bb9e63a821d407388cce83949b9af3e3b0434eaf0e09406b5c3af0290f997405d0c51be69544afb240d48eeab1736cda0432e8ff9e23ece5d70b38ccc9d43cd923e5e3e2f62d1d873c9141ef01f89b6de1336f5bc71852d574e46d370a0b1e64f6c41eeb8d40cf96c524a62965661f2ef87e67234d0a657027cce8d4f238ea896dde273b7537b508674a366c66b3789d9828b0ce903482f98a46ec358108fbbb68fd94f8f2baa73c723baf21922a850e45511f5a2d3f62f164f8c905b335a6cbf76131d2430237e17ad6abc76d2a6329c1ec5463ee07e397f503f9c1cea028465b2950ea444b15c5eab567d5a69ea2925685694df00405f1fc711872373d6eb50a09fbfb05b2703ae0a0b4edb86aedb216db17a8760be0848eb3e09c7027110ad842c502441c97afa14a844406fcfec754a25658c126b78788fd98ac020bac92d0e7792bb5ffed06b697d847f61d984f905d9ba87038fd5318d39055c82fef9bdd33315a541c0ec4363e6cc0687005871355dfa573380bd03b840c48c8ba3830e7cace72f91a5002218c617294e8c8bc687d5216de2c6e57ddc1d7c81a0299ed49c3d74759416bc8426f30e2af5622895c531b4e1c11d3a81b262fc76ef506ee6d88e5991d0de8cb9dd162d97c58b175e3bc4584f309b6b283ebaf45fbb1e448969ace9be62adf67ddf58614925741deb6a1ba7def15d5095164c885763fa83cdf776d436382821a17bc5563a5b6f6dfcdac504ade3427fdbfca3cea23063eb138c5055c6cad9c4252b23d12c12293308eff7d9124272f12e731077b74317ef2543c33b86194db1da5f6a7e1eee0656672c81685fe05323f85deb8c07c193c37a73d76f6114967913a2bdce11995f183e769f429673d5ce415ecae4ba42b417ea3a501b44694f46efddff2fcca952b097f3852d3d80e8ec18c7b52c514d42047f1f0b2a90cb8c0c7391cf9479cd7fd5bfe1d3db8f201591c865ea7065d54304519f8bb268bddbeaf3afae54edcd01a833ed0a9ef1a3eddbeeee5eca5deee4bf1789c435e1241e0d71186d8f0f62d74729dfc3119fb23691c7009b9283b268766e8d491716d3c1993e6ecf458def8f762af3e35570726cdab2c837ebeac5bea4be1d6f0488034907374d81a61a34f1c4db397d4c09b2d2206730664d58be0676dad1fee0e990c264a7410a2cdb6b55653c1df72ef562bb74bb185372334a4ef5f6d18e2ece54086e62b04985dd794b7117b0be9217f366250fe928c45d8d5aa35f0a142754907ff3c598410199b589b28cd851b22041868f8118482c6b4a5a61a81c8aaca128953179c20f73a44022d9976bdc34af10b7901c670e1d75d726eb88d000950b3c963f0f7a6ca24994bdc07ae2f78b4d3032c4bd8ab70e1f25af77af57dd340c8e6c8a101dfc5e8dd03314566db90b8701ce36db31fe6ea3cd9308db9aa43a8af5c41a8f0a6509bfe00f0e7b486c0ab8a26596ea9e1915e53da3479e9d13c3c920505e2449e325810ff6ca855fe4b7c6e30f296a269868a7fca8f5b1e269c0116304df31729559a270e713509d3a6d5dc02588961eff7897d87eb6ac72350ef9f52640647cbd23136919a994dfd1979d516a49e69721e80690d41e06229e9bc2dbaf9a2abf4b89388db2485595409d62b3d7aca02c051fcad8073cfd67210cd423a31888afc4a444d9d3adf3d6c5da7bf299bd48a740b7790075268312ab8072c72421de5a6437fa5e25431ef951847b411a69b867d9ea22ec1b2f28e96617129e36eefaea9e8126bdc6a42b99072902b25bc1af391f3c1f2284a95da92b5883d1b3a40794b2358b2e7a70fca22da64ce361ab3843f4d8ddadede39d82bb1a8109f89b6d9aa117b8f365de43895de0baa38ef3ab5b61c117a3465a017a9c8ba4c227659b41fdf145206d5c960f49dd45b3992f83f26143dbdbd335604a1a14daf238ae43c249783f694feaf560aaae20f350287977eb71c81b10ecd039aad99cfa9ed84a04301cb30869e1dc7fa1dc6383afb5bc126020586dcccba32dd054cd9a3f3b834ca9678d6802c48b1da97d6ed172b7c2d8e7e4b06d183a2575b790749d0970c54966407fa8f59072c729de6712eb53fe3a278688a70494569e54a0f0d269935aec6c897bef4d368c1f67d57e40375ae56b8d9310d553ed77d406dedc3f0393e5a321b71caee6a5bb7078b50351d49a0d53bc2993cbf1fb5d1da9bb76fe46a7031d5e5d43fadbf54bc17c1ef38132d17b87cab6d707ddfa1f01df1724ad37957e989c44f1ff71426367f953160062da5280948d8c6c4acc7e6a1aa421f0f9ec179a44146750060be4be6755f850a4b4d5cde54a974ea4e57ee4132d2ab2510c300f21930d6bbbf211d1add80f93356f1fbeac493ccab752b70bbed821ce49965c19284d7aacd78fbf3ff864e91042721e8a9cc32557851feb0e0190c5dfbf4cb1b8f47d37e7e653ec6ff8a4059053d9b2633fff31ca4fc5724ce6b4422318128cdf01897d321e86f47cdf748b1267d96caeafde5dbd3db1f0668b09ccd532a22f0205494716a786219fb4c801c39316997737610193c3f9ffcfd4e23d38aac12cd7b95b8d256d774101650a6ca191e377462986563fdabf9b23529f7c84c6b200b9101b3a5096bca5f377981fb20f89af9722f79c860d2059a0ec209cf3a7925ad0798cab655eca62fe73ff3d91ca568aeddb2ef391a7c78ecf104d32d785b9ca145d97e35879df3534a7d1e0b25de9ba0a37472c3b4c0b9c3bc25cbbf78d91881b6f94ee70e4abf090211251c3393debd38d311881c7583bee07e605ef0e55c62f0508ccc2d26518cd568e1ef038df2fd18a8d7563806aa9d994a611f642d5c397388d1dd3e78bc7a4515c5b105c6503ff1ee548f2435ad9148d7fb94c9222b0908f445537a6667047f6d501c104c88d6d0682d82d3d664826dc9565db101a220aa8f90572eb798468a82a2ab2caad6108c09ee6aee7851b4a2d2d3b7c3ca3c56a80003c8471f90bfa4ac628b0a57dbd4c327826c8a97bc7285f94bcddb966177346f1792c4bd7088aa0353f33c15552f9124318b8433d01bb53ba04ba1cc9eb91d83b918e32fea39fbe908fa0e10c10cbbe1717a9441c6299c4fc087c222208bd4fa8f3be66d2075f623b5131e8b254cbff2c92a83dff1728c81dd22a9570f590e497cb2d640042cb879a9301812dbcd70c440610057bbfdd0cc4d31d1faf5786419b53841c4adc43f2b2352";

        assembly {
            // TODO: check gas consumption against static modexp
            function powermod(base, exponent, modulus) -> result {
                result := 1
                for {
                    let count := 1
                } lt(count, add(exponent, 0x01)) {
                    count := add(count, count)
                } {
                    if and(exponent, count) {
                        result := mulmod(result, base, modulus)
                    }
                    base := mulmod(base, base, modulus)
                }
            }

            function get_round_constant(i_mul_0x20, j, round_constants_ptr)
                -> result
            {
                result := mload(
                    add(
                        add(round_constants_ptr, 0x20),
                        add(mul(i_mul_0x20, 3), mul(j, 0x20))
                    )
                )
            }

            function get_matrix_constant(i, j, mds_ptr) -> result {
                result := mload(
                    add(
                        add(mds_ptr, 0x20),
                        add(
                            // 0x60 = 3 * 0x20
                            mul(i, 0x60),
                            mul(j, 0x20)
                        )
                    )
                )
            }

            gates_evaluation := 0
            for {
                let i := 0
            } lt(i, mul(0xa0, mload(mload(add(params, 0x60))))) {
                i := add(i, 0xa0)
            } {
                mstore(
                    // params.gate_evaluation
                    add(params, 0xa0),
                    0
                )

                //======================================================================================================
                // 1. var(W3, 0) - (var(W0, 0).pow(sbox_alpha) * mds[0][0] + var(W1, 0).pow(sbox_alpha) * mds[0][1] +
                //  var(W2, 0).pow(sbox_alpha)* mds[0][2] + round_constant[z][0])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W3, 0)
                        mload(mload(add(assignment_pointers, W3_rot0))),
                        // -(var(W0, 0).pow(sbox_alpha) * mds[0][0] + var(W1, 0).pow(sbox_alpha) * mds[0][1] +
                        //  var(W2, 0).pow(sbox_alpha)* mds[0][2] + round_constant[z][0])
                        sub(
                            mload(params),
                            // var(W0, 0).pow(sbox_alpha) * mds[0][0] + var(W1, 0).pow(sbox_alpha) * mds[0][1] +
                            //  var(W2, 0).pow(sbox_alpha)* mds[0][2] + round_constant[z][0]
                            addmod(
                                // var(W0, 0).pow(sbox_alpha) * mds[0][0]
                                mulmod(
                                    // var(W0, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W0, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W0_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[0][0]
                                    get_matrix_constant(
                                        0,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W1, 0).pow(sbox_alpha) * mds[0][1] +
                                //  var(W2, 0).pow(sbox_alpha)* mds[0][2] + round_constant[z][0]
                                addmod(
                                    // var(W1, 0).pow(sbox_alpha) * mds[0][1]
                                    mulmod(
                                        // var(W1, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W1, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W1_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[0][1]
                                        get_matrix_constant(
                                            0,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W2, 0).pow(sbox_alpha)* mds[0][2] + round_constant[z][0]
                                    addmod(
                                        // var(W2, 0).pow(sbox_alpha) * mds[0][2]
                                        mulmod(
                                            // var(W2, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W2, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W2_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[0][2]
                                            get_matrix_constant(
                                                0,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z][0]
                                        get_round_constant(
                                            i,
                                            0,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 2. var(W4, 0) - (var(W0, 0).pow(sbox_alpha) * mds[1][0] + var(W1, 0).pow(sbox_alpha) * mds[1][1] +
                //  var(W2, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z][1])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W4, 0)
                        mload(mload(add(assignment_pointers, W4_rot0))),
                        // -(var(W0, 0).pow(sbox_alpha) * mds[1][0] + var(W1, 0).pow(sbox_alpha) * mds[1][1] +
                        //  var(W2, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z][1])
                        sub(
                            mload(params),
                            // var(W0, 0).pow(sbox_alpha) * mds[1][0] + var(W1, 0).pow(sbox_alpha) * mds[1][1] +
                            //  var(W2, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z][1]
                            addmod(
                                // var(W0, 0).pow(sbox_alpha) * mds[1][0]
                                mulmod(
                                    // var(W0, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W0, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W0_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[1][0]
                                    get_matrix_constant(
                                        1,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W1, 0).pow(sbox_alpha) * mds[1][1] +
                                //  var(W2, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z][1]
                                addmod(
                                    // var(W1, 0).pow(sbox_alpha) * mds[1][1]
                                    mulmod(
                                        // var(W1, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W1, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W1_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[1][1]
                                        get_matrix_constant(
                                            1,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W2, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z][1]
                                    addmod(
                                        // var(W2, 0).pow(sbox_alpha) * mds[1][2]
                                        mulmod(
                                            // var(W2, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W2, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W2_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[1][2]
                                            get_matrix_constant(
                                                1,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z][1]
                                        get_round_constant(
                                            i,
                                            1,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 3. var(W5, 0) - (var(W0, 0).pow(sbox_alpha) * mds[2][0] + var(W1, 0).pow(sbox_alpha) * mds[2][1] +
                //  var(W2, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z][2])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W5, 0)
                        mload(mload(add(assignment_pointers, W5_rot0))),
                        // -(var(W0, 0).pow(sbox_alpha) * mds[2][0] + var(W1, 0).pow(sbox_alpha) * mds[2][1] +
                        //  var(W2, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z][2])
                        sub(
                            mload(params),
                            // var(W0, 0).pow(sbox_alpha) * mds[2][0] + var(W1, 0).pow(sbox_alpha) * mds[2][1] +
                            //  var(W2, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z][2]
                            addmod(
                                // var(W0, 0).pow(sbox_alpha) * mds[2][0]
                                mulmod(
                                    // var(W0, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W0, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W0_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[2][0]
                                    get_matrix_constant(
                                        2,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W1, 0).pow(sbox_alpha) * mds[2][1] +
                                //  var(W2, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z][2]
                                addmod(
                                    // var(W1, 0).pow(sbox_alpha) * mds[2][1]
                                    mulmod(
                                        // var(W1, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W1, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W1_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[2][1]
                                        get_matrix_constant(
                                            2,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W2, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z][2]
                                    addmod(
                                        // var(W2, 0).pow(sbox_alpha) * mds[2][2]
                                        mulmod(
                                            // var(W2, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W2, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W2_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[2][2]
                                            get_matrix_constant(
                                                2,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z][2]
                                        get_round_constant(
                                            i,
                                            2,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 4. var(W6, 0) - (var(W3, 0).pow(sbox_alpha) * mds[0][0] + var(W4, 0).pow(sbox_alpha) * mds[0][1] +
                //  var(W5, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 1][0])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W6, 0)
                        mload(mload(add(assignment_pointers, W6_rot0))),
                        // -(var(W3, 0).pow(sbox_alpha) * mds[0][0] + var(W4, 0).pow(sbox_alpha) * mds[0][1] +
                        //  var(W5, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 1][0])
                        sub(
                            mload(params),
                            // var(W3, 0).pow(sbox_alpha) * mds[0][0] + var(W4, 0).pow(sbox_alpha) * mds[0][1] +
                            //  var(W5, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 1][0]
                            addmod(
                                // var(W3, 0).pow(sbox_alpha) * mds[0][0]
                                mulmod(
                                    // var(W3, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W3, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W3_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[0][0]
                                    get_matrix_constant(
                                        0,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W4, 0).pow(sbox_alpha) * mds[0][1] +
                                //  var(W5, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 1][0]
                                addmod(
                                    // var(W4, 0).pow(sbox_alpha) * mds[0][1]
                                    mulmod(
                                        // var(W4, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W4, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W4_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[0][1]
                                        get_matrix_constant(
                                            0,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W5, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 1][0]
                                    addmod(
                                        // var(W5, 0).pow(sbox_alpha) * mds[0][2]
                                        mulmod(
                                            // var(W5, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W5, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W5_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[0][2]
                                            get_matrix_constant(
                                                0,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 1][0]
                                        get_round_constant(
                                            add(i, 0x20),
                                            0,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 5. var(W7, 0) - (var(W3, 0).pow(sbox_alpha) * mds[1][0] + var(W4, 0).pow(sbox_alpha) * mds[1][1] +
                //  var(W5, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 1][1])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W7, 0)
                        mload(mload(add(assignment_pointers, W7_rot0))),
                        // -(var(W3, 0).pow(sbox_alpha) * mds[1][0] + var(W4, 0).pow(sbox_alpha) * mds[1][1] +
                        //  var(W5, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 1][1])
                        sub(
                            mload(params),
                            // var(W3, 0).pow(sbox_alpha) * mds[1][0] + var(W4, 0).pow(sbox_alpha) * mds[1][1] +
                            //  var(W5, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 1][1]
                            addmod(
                                // var(W3, 0).pow(sbox_alpha) * mds[1][0]
                                mulmod(
                                    // var(W3, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W3, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W3_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[1][0]
                                    get_matrix_constant(
                                        1,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W4, 0).pow(sbox_alpha) * mds[1][1] +
                                //  var(W5, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 1][1]
                                addmod(
                                    // var(W4, 0).pow(sbox_alpha) * mds[1][1]
                                    mulmod(
                                        // var(W4, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W4, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W4_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[1][1]
                                        get_matrix_constant(
                                            1,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W5, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 1][1]
                                    addmod(
                                        // var(W5, 0).pow(sbox_alpha) * mds[1][2]
                                        mulmod(
                                            // var(W5, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W5, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W5_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[1][2]
                                            get_matrix_constant(
                                                1,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 1][1]
                                        get_round_constant(
                                            add(i, 0x20),
                                            1,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 6. var(W8, 0) - (var(W3, 0).pow(sbox_alpha) * mds[2][0] + var(W4, 0).pow(sbox_alpha) * mds[2][1] +
                //  var(W5, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 1][2])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W8, 0)
                        mload(mload(add(assignment_pointers, W8_rot0))),
                        // -(var(W3, 0).pow(sbox_alpha) * mds[2][0] + var(W4, 0).pow(sbox_alpha) * mds[2][1] +
                        //  var(W5, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 1][2])
                        sub(
                            mload(params),
                            // var(W3, 0).pow(sbox_alpha) * mds[2][0] + var(W4, 0).pow(sbox_alpha) * mds[2][1] +
                            //  var(W5, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 1][2]
                            addmod(
                                // var(W3, 0).pow(sbox_alpha) * mds[2][0]
                                mulmod(
                                    // var(W3, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W3, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W3_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[2][0]
                                    get_matrix_constant(
                                        2,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W4, 0).pow(sbox_alpha) * mds[2][1] +
                                //  var(W5, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 1][2]
                                addmod(
                                    // var(W4, 0).pow(sbox_alpha) * mds[2][1]
                                    mulmod(
                                        // var(W4, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W4, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W4_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[2][1]
                                        get_matrix_constant(
                                            2,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W5, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 1][2]
                                    addmod(
                                        // var(W5, 0).pow(sbox_alpha) * mds[2][2]
                                        mulmod(
                                            // var(W5, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W5, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W5_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[2][2]
                                            get_matrix_constant(
                                                2,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 1][2]
                                        get_round_constant(
                                            add(i, 0x20),
                                            2,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 7. var(W9, 0) - (var(W6, 0).pow(sbox_alpha) * mds[0][0] + var(W7, 0).pow(sbox_alpha) * mds[0][1] +
                //  var(W8, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 2][0])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W9, 0)
                        mload(mload(add(assignment_pointers, W9_rot0))),
                        // -(var(W6, 0).pow(sbox_alpha) * mds[0][0] + var(W7, 0).pow(sbox_alpha) * mds[0][1] +
                        //  var(W8, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 2][0])
                        sub(
                            mload(params),
                            // var(W6, 0).pow(sbox_alpha) * mds[0][0] + var(W7, 0).pow(sbox_alpha) * mds[0][1] +
                            //  var(W8, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 2][0]
                            addmod(
                                // var(W6, 0).pow(sbox_alpha) * mds[0][0]
                                mulmod(
                                    // var(W6, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W6, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W6_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[0][0]
                                    get_matrix_constant(
                                        0,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W7, 0).pow(sbox_alpha) * mds[0][1] +
                                //  var(W8, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 2][0]
                                addmod(
                                    // var(W7, 0).pow(sbox_alpha) * mds[0][1]
                                    mulmod(
                                        // var(W7, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W7, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W7_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[0][1]
                                        get_matrix_constant(
                                            0,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W8, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 2][0]
                                    addmod(
                                        // var(W8, 0).pow(sbox_alpha) * mds[0][2]
                                        mulmod(
                                            // var(W8, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W8, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W8_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[0][2]
                                            get_matrix_constant(
                                                0,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 2][0]
                                        get_round_constant(
                                            add(i, 0x40),
                                            0,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 8. var(W10, 0) - (var(W6, 0).pow(sbox_alpha) * mds[1][0] + var(W7, 0).pow(sbox_alpha) * mds[1][1] +
                //  var(W8, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 2][1])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W10, 0)
                        mload(mload(add(assignment_pointers, W10_rot0))),
                        // -(var(W6, 0).pow(sbox_alpha) * mds[1][0] + var(W7, 0).pow(sbox_alpha) * mds[1][1] +
                        //  var(W8, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 2][1])
                        sub(
                            mload(params),
                            // var(W6, 0).pow(sbox_alpha) * mds[1][0] + var(W7, 0).pow(sbox_alpha) * mds[1][1] +
                            //  var(W8, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 2][1]
                            addmod(
                                // var(W6, 0).pow(sbox_alpha) * mds[1][0]
                                mulmod(
                                    // var(W6, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W6, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W6_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[1][0]
                                    get_matrix_constant(
                                        1,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W7, 0).pow(sbox_alpha) * mds[1][1] +
                                //  var(W8, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 2][1]
                                addmod(
                                    // var(W7, 0).pow(sbox_alpha) * mds[1][1]
                                    mulmod(
                                        // var(W7, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W7, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W7_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[1][1]
                                        get_matrix_constant(
                                            1,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W8, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 2][1]
                                    addmod(
                                        // var(W8, 0).pow(sbox_alpha) * mds[1][2]
                                        mulmod(
                                            // var(W8, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W8, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W8_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[1][2]
                                            get_matrix_constant(
                                                1,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 2][1]
                                        get_round_constant(
                                            add(i, 0x40),
                                            1,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 9. var(W11, 0) - (var(W6, 0).pow(sbox_alpha) * mds[2][0] + var(W7, 0).pow(sbox_alpha) * mds[2][1] +
                //  var(W8, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 2][2])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W11, 0)
                        mload(mload(add(assignment_pointers, W11_rot0))),
                        // -(var(W6, 0).pow(sbox_alpha) * mds[2][0] + var(W7, 0).pow(sbox_alpha) * mds[2][1] +
                        //  var(W8, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 2][2])
                        sub(
                            mload(params),
                            // var(W6, 0).pow(sbox_alpha) * mds[2][0] + var(W7, 0).pow(sbox_alpha) * mds[2][1] +
                            //  var(W8, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 2][2]
                            addmod(
                                // var(W6, 0).pow(sbox_alpha) * mds[2][0]
                                mulmod(
                                    // var(W6, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W6, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W6_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[2][0]
                                    get_matrix_constant(
                                        2,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W7, 0).pow(sbox_alpha) * mds[2][1] +
                                //  var(W8, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 2][2]
                                addmod(
                                    // var(W7, 0).pow(sbox_alpha) * mds[2][1]
                                    mulmod(
                                        // var(W7, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W7, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W7_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[2][1]
                                        get_matrix_constant(
                                            2,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W8, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 2][2]
                                    addmod(
                                        // var(W8, 0).pow(sbox_alpha) * mds[2][2]
                                        mulmod(
                                            // var(W8, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W8, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W8_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[2][2]
                                            get_matrix_constant(
                                                2,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 2][2]
                                        get_round_constant(
                                            add(i, 0x40),
                                            2,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 10. var(W12, 0) - (var(W9, 0).pow(sbox_alpha) * mds[0][0] + var(W10, 0).pow(sbox_alpha) * mds[0][1] +
                //  var(W11, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 3][0])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W12, 0)
                        mload(mload(add(assignment_pointers, W12_rot0))),
                        // -(var(W9, 0).pow(sbox_alpha) * mds[0][0] + var(W10, 0).pow(sbox_alpha) * mds[0][1] +
                        //  var(W11, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 3][0])
                        sub(
                            mload(params),
                            // var(W9, 0).pow(sbox_alpha) * mds[0][0] + var(W10, 0).pow(sbox_alpha) * mds[0][1] +
                            //  var(W11, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 3][0]
                            addmod(
                                // var(W9, 0).pow(sbox_alpha) * mds[0][0]
                                mulmod(
                                    // var(W9, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W9, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W9_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[0][0]
                                    get_matrix_constant(
                                        0,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W10, 0).pow(sbox_alpha) * mds[0][1] +
                                //  var(W11, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 3][0]
                                addmod(
                                    // var(W10, 0).pow(sbox_alpha) * mds[0][1]
                                    mulmod(
                                        // var(W10, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W10, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W10_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[0][1]
                                        get_matrix_constant(
                                            0,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W11, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 3][0]
                                    addmod(
                                        // var(W11, 0).pow(sbox_alpha) * mds[0][2]
                                        mulmod(
                                            // var(W11, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W11, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W11_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[0][2]
                                            get_matrix_constant(
                                                0,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 3][0]
                                        get_round_constant(
                                            add(i, 0x60),
                                            0,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 11. var(W13, 0) - (var(W9, 0).pow(sbox_alpha) * mds[1][0] + var(W10, 0).pow(sbox_alpha) * mds[1][1] +
                //  var(W11, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 3][1])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W13, 0)
                        mload(mload(add(assignment_pointers, W13_rot0))),
                        // -(var(W9, 0).pow(sbox_alpha) * mds[1][0] + var(W10, 0).pow(sbox_alpha) * mds[1][1] +
                        //  var(W11, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 3][1])
                        sub(
                            mload(params),
                            // var(W9, 0).pow(sbox_alpha) * mds[1][0] + var(W10, 0).pow(sbox_alpha) * mds[1][1] +
                            //  var(W11, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 3][1]
                            addmod(
                                // var(W9, 0).pow(sbox_alpha) * mds[1][0]
                                mulmod(
                                    // var(W9, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W9, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W9_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[1][0]
                                    get_matrix_constant(
                                        1,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W10, 0).pow(sbox_alpha) * mds[1][1] +
                                //  var(W11, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 3][1]
                                addmod(
                                    // var(W10, 0).pow(sbox_alpha) * mds[1][1]
                                    mulmod(
                                        // var(W10, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W10, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W10_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[1][1]
                                        get_matrix_constant(
                                            1,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W11, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 3][1]
                                    addmod(
                                        // var(W11, 0).pow(sbox_alpha) * mds[1][2]
                                        mulmod(
                                            // var(W11, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W11, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W11_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[1][2]
                                            get_matrix_constant(
                                                1,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 3][1]
                                        get_round_constant(
                                            add(i, 0x60),
                                            1,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 12. var(W14, 0) - (var(W9, 0).pow(sbox_alpha) * mds[2][0] + var(W10, 0).pow(sbox_alpha) * mds[2][1] +
                //  var(W11, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 3][2])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W14, 0)
                        mload(mload(add(assignment_pointers, W14_rot0))),
                        // -(var(W9, 0).pow(sbox_alpha) * mds[2][0] + var(W10, 0).pow(sbox_alpha) * mds[2][1] +
                        //  var(W11, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 3][2])
                        sub(
                            mload(params),
                            // var(W9, 0).pow(sbox_alpha) * mds[2][0] + var(W10, 0).pow(sbox_alpha) * mds[2][1] +
                            //  var(W11, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 3][2]
                            addmod(
                                // var(W9, 0).pow(sbox_alpha) * mds[2][0]
                                mulmod(
                                    // var(W9, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W9, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W9_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[2][0]
                                    get_matrix_constant(
                                        2,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W10, 0).pow(sbox_alpha) * mds[2][1] +
                                //  var(W11, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 3][2]
                                addmod(
                                    // var(W10, 0).pow(sbox_alpha) * mds[2][1]
                                    mulmod(
                                        // var(W10, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W10, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W10_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[2][1]
                                        get_matrix_constant(
                                            2,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W11, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 3][2]
                                    addmod(
                                        // var(W11, 0).pow(sbox_alpha) * mds[2][2]
                                        mulmod(
                                            // var(W11, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W11, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W11_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[2][2]
                                            get_matrix_constant(
                                                2,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 3][2]
                                        get_round_constant(
                                            add(i, 0x60),
                                            2,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 13. var(W0, +1) - (var(W12, 0).pow(sbox_alpha) * mds[0][0] + var(W13, 0).pow(sbox_alpha) * mds[0][1] +
                //  var(W14, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 4][0])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W0, +1)
                        mload(mload(add(assignment_pointers, W0_rot1))),
                        // -(var(W12, 0).pow(sbox_alpha) * mds[0][0] + var(W13, 0).pow(sbox_alpha) * mds[0][1] +
                        //  var(W14, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 4][0])
                        sub(
                            mload(params),
                            // var(W12, 0).pow(sbox_alpha) * mds[0][0] + var(W13, 0).pow(sbox_alpha) * mds[0][1] +
                            //  var(W14, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 4][0]
                            addmod(
                                // var(W12, 0).pow(sbox_alpha) * mds[0][0]
                                mulmod(
                                    // var(W12, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W12, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W12_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[0][0]
                                    get_matrix_constant(
                                        0,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W13, 0).pow(sbox_alpha) * mds[0][1] +
                                //  var(W14, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 4][0]
                                addmod(
                                    // var(W13, 0).pow(sbox_alpha) * mds[0][1]
                                    mulmod(
                                        // var(W13, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W13, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W13_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[0][1]
                                        get_matrix_constant(
                                            0,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W14, 0).pow(sbox_alpha) * mds[0][2] + round_constant[z + 4][0]
                                    addmod(
                                        // var(W14, 0).pow(sbox_alpha) * mds[0][2]
                                        mulmod(
                                            // var(W14, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W14, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W14_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[0][2]
                                            get_matrix_constant(
                                                0,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 4][0]
                                        get_round_constant(
                                            add(i, 0x80),
                                            0,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 14. var(W1, +1) - (var(W12, 0).pow(sbox_alpha) * mds[1][0] + var(W13, 0).pow(sbox_alpha) * mds[1][1] +
                //  var(W14, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 4][1])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W1, +1)
                        mload(mload(add(assignment_pointers, W1_rot1))),
                        // -(var(W12, 0).pow(sbox_alpha) * mds[1][0] + var(W13, 0).pow(sbox_alpha) * mds[1][1] +
                        //  var(W14, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 4][1])
                        sub(
                            mload(params),
                            // var(W12, 0).pow(sbox_alpha) * mds[1][0] + var(W13, 0).pow(sbox_alpha) * mds[1][1] +
                            //  var(W14, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 4][1]
                            addmod(
                                // var(W12, 0).pow(sbox_alpha) * mds[1][0]
                                mulmod(
                                    // var(W12, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W12, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W12_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[1][0]
                                    get_matrix_constant(
                                        1,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W13, 0).pow(sbox_alpha) * mds[1][1] +
                                //  var(W14, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 4][1]
                                addmod(
                                    // var(W13, 0).pow(sbox_alpha) * mds[1][1]
                                    mulmod(
                                        // var(W13, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W13, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W13_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[1][1]
                                        get_matrix_constant(
                                            1,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W14, 0).pow(sbox_alpha) * mds[1][2] + round_constant[z + 4][1]
                                    addmod(
                                        // var(W14, 0).pow(sbox_alpha) * mds[1][2]
                                        mulmod(
                                            // var(W14, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W14, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W14_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[1][2]
                                            get_matrix_constant(
                                                1,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 4][1]
                                        get_round_constant(
                                            add(i, 0x80),
                                            1,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //======================================================================================================
                // 15. var(W2, +1) - (var(W12, 0).pow(sbox_alpha) * mds[2][0] + var(W13, 0).pow(sbox_alpha) * mds[2][1] +
                //  var(W14, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 4][2])
                mstore(
                    add(params, 0x80),
                    addmod(
                        // var(W2, +1)
                        mload(mload(add(assignment_pointers, W2_rot1))),
                        // -(var(W12, 0).pow(sbox_alpha) * mds[2][0] + var(W13, 0).pow(sbox_alpha) * mds[2][1] +
                        //  var(W14, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 4][2])
                        sub(
                            mload(params),
                            // var(W12, 0).pow(sbox_alpha) * mds[2][0] + var(W13, 0).pow(sbox_alpha) * mds[2][1] +
                            //  var(W14, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 4][2]
                            addmod(
                                // var(W12, 0).pow(sbox_alpha) * mds[2][0]
                                mulmod(
                                    // var(W12, 0).pow(sbox_alpha)
                                    powermod(
                                        // var(W12, 0)
                                        mload(
                                            mload(
                                                add(
                                                    assignment_pointers,
                                                    W12_rot0
                                                )
                                            )
                                        ),
                                        // sbox_alpha
                                        SBOX,
                                        mload(params)
                                    ),
                                    // mds[2][0]
                                    get_matrix_constant(
                                        2,
                                        0,
                                        mload(add(params, 0xc0))
                                    ),
                                    mload(params)
                                ),
                                // var(W13, 0).pow(sbox_alpha) * mds[2][1] +
                                //  var(W14, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 4][2]
                                addmod(
                                    // var(W13, 0).pow(sbox_alpha) * mds[2][1]
                                    mulmod(
                                        // var(W13, 0).pow(sbox_alpha)
                                        powermod(
                                            // var(W13, 0)
                                            mload(
                                                mload(
                                                    add(
                                                        assignment_pointers,
                                                        W13_rot0
                                                    )
                                                )
                                            ),
                                            // sbox_alpha
                                            SBOX,
                                            mload(params)
                                        ),
                                        // mds[2][1]
                                        get_matrix_constant(
                                            2,
                                            1,
                                            mload(add(params, 0xc0))
                                        ),
                                        mload(params)
                                    ),
                                    // var(W14, 0).pow(sbox_alpha) * mds[2][2] + round_constant[z + 4][2]
                                    addmod(
                                        // var(W14, 0).pow(sbox_alpha) * mds[2][2]
                                        mulmod(
                                            // var(W14, 0).pow(sbox_alpha)
                                            powermod(
                                                // var(W14, 0)
                                                mload(
                                                    mload(
                                                        add(
                                                            assignment_pointers,
                                                            W14_rot0
                                                        )
                                                    )
                                                ),
                                                // sbox_alpha
                                                SBOX,
                                                mload(params)
                                            ),
                                            // mds[2][2]
                                            get_matrix_constant(
                                                2,
                                                2,
                                                mload(add(params, 0xc0))
                                            ),
                                            mload(params)
                                        ),
                                        // round_constant[z + 4][2]
                                        get_round_constant(
                                            add(i, 0x80),
                                            2,
                                            mload(add(params, 0xe0))
                                        ),
                                        mload(params)
                                    ),
                                    mload(params)
                                ),
                                mload(params)
                            )
                        ),
                        mload(params)
                    )
                )
                // gate_evaluation += constraint_eval * theta_acc
                mstore(
                    add(params, 0xa0),
                    addmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        mulmod(
                            // constraint_eval
                            mload(add(params, 0x80)),
                            // theta_acc
                            mload(add(params, 0x20)),
                            mload(params)
                        ),
                        mload(params)
                    )
                )
                // theta_acc *= theta
                mstore(
                    // params.theta_acc
                    add(params, 0x20),
                    // theta_acc * theta
                    mulmod(
                        // theta_acc
                        mload(add(params, 0x20)),
                        // theta
                        mload(add(params, 0x40)),
                        mload(params)
                    )
                )

                //==========================================================================================================
                // add selector evaluation
                mstore(
                    add(params, 0xa0),
                    mulmod(
                        // gate_evaluation
                        mload(add(params, 0xa0)),
                        // proof.eval_proof.selector[i].z[0]
                        mload(
                            mload(
                                add(
                                    mload(add(params, 0x60)),
                                    add(0x20, div(i, 5))
                                )
                            )
                        ),
                        mload(params)
                    )
                )

                gates_evaluation := addmod(
                    gates_evaluation,
                    // gate_evaluation
                    mload(add(params, 0xa0)),
                    mload(params)
                )
            }
        }
    }
}
