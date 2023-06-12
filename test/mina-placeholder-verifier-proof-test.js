const {
    time,
    loadFixture,
} = require("@nomicfoundation/hardhat-network-helpers");
const {anyValue} = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const {expect} = require("chai");
const hre = require('hardhat')
const fs = require("fs");
const path = require("path");
const losslessJSON = require("lossless-json")
const {BigNumber} = require("ethers");
const {getNamedAccounts} = hre

/* global BigInt */

describe('Mina state proof validation tests', function () {
    const {deployments, getNamedAccounts} = hre;
    const {deploy} = deployments;

    function loadParamsFromFile(jsonFile) {
        const named_params = losslessJSON.parse(fs.readFileSync(jsonFile, 'utf8'));
        params = {};
        params.init_params = [];
        params.init_params.push(BigInt(named_params.modulus.value));
        params.init_params.push(BigInt(named_params.r.value));
        params.init_params.push(BigInt(named_params.max_degree.value));
        params.init_params.push(BigInt(named_params.lambda.value));
        params.init_params.push(BigInt(named_params.rows_amount.value));
        params.init_params.push(BigInt(named_params.omega.value));
        params.init_params.push(BigInt(named_params.D_omegas.length));
        for (i in named_params.D_omegas) {
            params.init_params.push(BigInt(named_params.D_omegas[i].value))
        }
        params.init_params.push(named_params.step_list.length);
        for (i in named_params.step_list) {
            params.init_params.push(BigInt(named_params.step_list[i].value))
        }
        params.init_params.push(named_params.arithmetization_params.length);
        for (i in named_params.arithmetization_params) {
            params.init_params.push(BigInt(named_params.arithmetization_params[i].value))
        }

        params.columns_rotations = [];
        for (i in named_params.columns_rotations) {
            r = []
            for (j in named_params.columns_rotations[i]) {
                r.push(BigInt(named_params.columns_rotations[i][j].value));
            }
            params.columns_rotations.push(r);
        }
        return params;
    }

    function loadPublicInputsFromFiles(file1, file2){
        return [[],[]];
    }

    function prepareBaseProofPublicInputs(kimchi, kimchi_const){
        let kimchi_proof = kimchi.data.bestChain[0].protocolStateProof.json.proof;

        let public_input = [];
        let evalRounds = 10;
        let maxPolySize = 1 << evalRounds;   


        for(i in kimchi_proof.messages.w_comm){
            for(j in kimchi_proof.messages.w_comm[i]){
                public_input.push(BigInt(kimchi_proof.messages.w_comm[i][j][0]));
                public_input.push(BigInt(kimchi_proof.messages.w_comm[i][j][1]));
            }
        }
        for(i in kimchi_proof.messages.z_comm){
            public_input.push(BigInt(kimchi_proof.messages.z_comm[i][0]));
            public_input.push(BigInt(kimchi_proof.messages.z_comm[i][1]));
            break; // TODO: ask, is it right?
        }
        for(i in kimchi_proof.messages.t_comm){
            public_input.push(BigInt(kimchi_proof.messages.t_comm[i][0]));
            public_input.push(BigInt(kimchi_proof.messages.t_comm[i][1]));
            break; //TODO: ask, is it right?
        }
        // TODO: Test it.
        if(kimchi_proof.messages.lookup){
            for(i in kimchi_proof.messages.lookup.sorted){
                for(j in kimchi_proof.messages.lookup.sorted[i]){
                    public_input.push(BigInt(kimchi_proof.messages.lookup.sorted[i][j][0]));
                    public_input.push(BigInt(kimchi_proof.messages.lookup.sorted[i][j][1]));
                }
            }
            for(i in kimchi_proof.messages.lookup.aggreg){
                public_input.push(BigInt(kimchi_proof.messages.lookup.aggreg[i][0]));
                public_input.push(BigInt(kimchi_proof.messages.lookup.aggreg[i][1]));
            }
            for(i in kimchi_proof.messages.lookup.runtime){
                public_input.push(BigInt(kimchi_proof.messages.lookup.runtime[i][0]));
                public_input.push(BigInt(kimchi_proof.messages.lookup.runtime[i][1]));
            }
        }
        // TODO: Check it. In mina-state-proof it was loop for( i = 0; i < circuit_proof.comm.table.parts.size(); i++)
        for(i in kimchi_proof.messages.z_comm){
            public_input.push(BigInt(kimchi_proof.messages.z_comm[i][0]));
            public_input.push(BigInt(kimchi_proof.messages.z_comm[i][1]));
        }
        let lrlen = kimchi_proof.openings.proof.lr.length > evalRounds ? evalRounds : kimchi_proof.openings.proof.lr.length;
        for( i = 0; i < lrlen; i++){
            public_input.push(BigInt(kimchi_proof.openings.proof.lr[i][0][0]));
            public_input.push(BigInt(kimchi_proof.openings.proof.lr[i][0][1]));

            public_input.push(BigInt(kimchi_proof.openings.proof.lr[i][1][0]));
            public_input.push(BigInt(kimchi_proof.openings.proof.lr[i][1][1]));
        }
        public_input.push(BigInt(kimchi_proof.openings.proof.delta[0]));
        public_input.push(BigInt(kimchi_proof.openings.proof.delta[1]));

        public_input.push(BigInt(kimchi_proof.openings.proof.challenge_polynomial_commitment[0]));
        public_input.push(BigInt(kimchi_proof.openings.proof.challenge_polynomial_commitment[1]));

        for( i = 0; i < 30; i++){
            public_input.push(BigInt(3));
        }
        // TODO process batched_proofs.

        for(i in kimchi.data.blockchainVerificationKey.commitments.sigma_comm){
            public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.sigma_comm[i][0]));
            public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.sigma_comm[i][1]));
        }
        for(i in kimchi.data.blockchainVerificationKey.commitments.coefficients_comm){
            public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.coefficients_comm[i][0]));
            public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.coefficients_comm[i][1]));
        }
        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.generic_comm[0]));
        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.generic_comm[1]));

        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.psm_comm[0]));
        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.psm_comm[1]));

        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.complete_add_comm[0]));
        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.complete_add_comm[1]));

        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.mul_comm[0]));
        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.mul_comm[1]));

        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.emul_comm[0]));
        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.emul_comm[1]));

        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.endomul_scalar_comm[0]));
        public_input.push(BigInt(kimchi.data.blockchainVerificationKey.commitments.endomul_scalar_comm[1]));

        // chacha_comm nul in example.
        // range_check_comm not found too.
        // 
        let point = [
            BigInt(kimchi.data.blockchainVerificationKey.commitments.sigma_comm[0][0]), 
            BigInt(kimchi.data.blockchainVerificationKey.commitments.sigma_comm[0][1])
        ];

//      Push point to public input.
//        Selector size 0
//        Lookup selector size 0
//        Lookup table size 0
//        Runtime table selector 1
        public_input.push(point[0]);
        public_input.push(point[1]);
//        One more time
        public_input.push(point[0]);
        public_input.push(point[1]);

        for(i = 0; i < maxPolySize; i++){
            public_input.push(point[0]);
            public_input.push(point[1]);
        }
            
        return public_input;
    }

    function prepareScalarProofPublicInputs(kimchi, kimchi_const){
        let kimchi_proof = kimchi.data.bestChain[0].protocolStateProof.json.proof;
        let public_input = [];
        public_input.push(BigInt(0));

        for( ev in [0,1]){
            for(i in kimchi_proof.openings.evals.w){
                public_input.push(BigInt(kimchi_proof.openings.evals.w[i][ev][0]));
            }

            public_input.push(BigInt(kimchi_proof.openings.evals.z[ev][0]));
            for(i in kimchi_proof.openings.evals.s){
                public_input.push(BigInt(kimchi_proof.openings.evals.s[i][ev][0]));
            }
            // TODO: add lookup processing
            public_input.push(BigInt(kimchi_proof.openings.evals.generic_selector[ev][0]));
            public_input.push(BigInt(kimchi_proof.openings.evals.poseidon_selector[ev][0]));
        }

        public_input.push(BigInt(2));
        public_input.push(BigInt(kimchi_proof.openings.ft_eval1));

        public_input.push(BigInt(2));
        public_input.push(BigInt(2));

        public_input.push(BigInt(0));
        public_input.push(BigInt(0));
        public_input.push(BigInt(0));
        public_input.push(BigInt(0));
        public_input.push(BigInt(0));
        public_input.push(BigInt(0));
        public_input.push(BigInt(0));

        public_input.push(BigInt(kimchi_const.verify_index.w));
        return public_input;
    }

    function getVerifierParams() {
        let params = {}

        params['proof'] = fs.readFileSync(path.resolve(__dirname, "./data/proof_state.bin"), 'utf8');

        params['init_params'] = [[24760, 21744], [], []];

        params['columns_rotations'] = [[], []]

        params['public_inputs'] = [[], []]

        // For proof 1
        let base_params = loadParamsFromFile(path.resolve(__dirname, "./data/verifier_params_state_base.json"));
        params['init_params'][1] = base_params.init_params;
        params['columns_rotations'][0] = base_params.columns_rotations;
        params['public_inputs'][0] = prepareBaseProofPublicInputs(
            losslessJSON.parse(fs.readFileSync(path.resolve(__dirname, "./data/kimchi.json"),"utf8")),
            losslessJSON.parse(fs.readFileSync(path.resolve(__dirname, "./data/kimchi_const.json"),"utf8"))
        );

        // For proof 2
        let scalar_params = loadParamsFromFile(path.resolve(__dirname, "./data/verifier_params_state_scalar.json"));
        params['init_params'][2] = scalar_params.init_params;
        params['columns_rotations'][1] = scalar_params.columns_rotations;
        params['public_inputs'][1] = prepareScalarProofPublicInputs(
            losslessJSON.parse(fs.readFileSync(path.resolve(__dirname, "./data/kimchi.json"),"utf8")),
            losslessJSON.parse(fs.readFileSync(path.resolve(__dirname, "./data/kimchi_const.json"),"utf8"))
        );

        return params;
    }

    function getVerifierParamsAccount() {
        let account_path_params = loadParamsFromFile(path.resolve(__dirname, './data/verifier_params_account.json'));

        account_path_params['proof'] = fs.readFileSync(path.resolve(__dirname, "./data/proof_account.bin"), 'utf8');
        account_path_params['public_inputs'] = [];

        return account_path_params;
    }

    describe('Ledger Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await expect(minaPlaceholderVerifierIF.verifyLedgerState("jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidationAccepted");
        });

        it("Should update and store proof ", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await minaPlaceholderVerifierIF.updateLedgerProof(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000})
        });

        it("Should validate previously updated & stored correct proof ", async function () {
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.isValidatedLedgerHash("jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", {gasLimit: 30_500_000})).to.equal(true);
        });
    })

    describe('Account Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await expect(minaPlaceholderVerifierIF.updateLedgerProof("jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidationAccepted");

            params = getVerifierParamsAccount();

            const accountData = {
                public_key: "B62qre3ersHfzQckNuibViWTGyyKwZseztqrjPjBv6SQF384Rg6ESAy",
                balance: {
                    liquid: 5000n,
                    locked: 0n
                },
                state: [
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x0000000000000000000000000000000000000000000000000000000000000002",
                    "0x0000000000000000000000000000000000000000000000000000000000000003",
                    "0x0000000000000000000000000000000000000000000000000000000000000004",
                    "0x0000000000000000000000000000000000000000000000000000000000000005",
                    "0x0000000000000000000000000000000000000000000000000000000000000006",
                    "0x0000000000000000000000000000000000000000000000000000000000000007",
                    "0x0000000000000000000000000000000000000000000000000000000000000008"
                ],
            };
            await expect(minaPlaceholderVerifierIF.verifyAccountState(accountData, "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", params['proof'],
                params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "AccountProofValidationAccepted");
        });
    });

    describe("Ledger Proof - Failures", function () {
        it("Should emit event on incorrect proof validation", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture'])

            params['proof'] = '0x4554480000000000000000000000000000000000000000000000000000000000'
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await expect(minaPlaceholderVerifierIF.verifyLedgerState(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidationFailed");
        });

        it("Should fail to update and store incorrect proof ", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);

            params['proof'] = '0x4554480000000000000000000000000000000000000000000000000000000000'
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.updateLedgerProof(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", 
                params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidationFailed");
        });

        it("Should fail for incorrect hash", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture'])

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.verifyLedgerState(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", 
                params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000})
            ).to.emit(minaPlaceholderVerifierIF, "InvalidLedgerHash");
        });
    })

    describe('Account Proof - Failures', function () {
        it("Should fail if incorrect ledger hash provided along with proof ", async function () {
            let params = getVerifierParamsAccount();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);

            const accountData = {
                public_key: "B62qre3ersHfzQckNuibViWTGyyKwZseztqrjPjBv6SQF384Rg6ESAy",
                balance: {
                    liquid: 5000n,
                    locked: 0n
                },
                state: [
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x0000000000000000000000000000000000000000000000000000000000000002",
                    "0x0000000000000000000000000000000000000000000000000000000000000003",
                    "0x0000000000000000000000000000000000000000000000000000000000000004",
                    "0x0000000000000000000000000000000000000000000000000000000000000005",
                    "0x0000000000000000000000000000000000000000000000000000000000000006",
                    "0x0000000000000000000000000000000000000000000000000000000000000007",
                    "0x0000000000000000000000000000000000000000000000000000000000000008"
                ],
            };
            await expect(minaPlaceholderVerifierIF.verifyAccountState(
                accountData, "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcA", 
                params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "InvalidLedgerHash");
        });

        it("Should fail with correct hash and incorrect proof ", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await expect(minaPlaceholderVerifierIF.updateLedgerProof("jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidationAccepted");

            params = getVerifierParamsAccount();

            const accountData = {
                public_key: "B62qre3ersHfzQckNuibViWTGyyKwZseztqrjPjBv6SQF384Rg6ESAy",
                balance: {
                    liquid: 5000n,
                    locked: 0n
                },
                state: [
                    "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "0x0000000000000000000000000000000000000000000000000000000000000002",
                    "0x0000000000000000000000000000000000000000000000000000000000000003",
                    "0x0000000000000000000000000000000000000000000000000000000000000004",
                    "0x0000000000000000000000000000000000000000000000000000000000000005",
                    "0x0000000000000000000000000000000000000000000000000000000000000006",
                    "0x0000000000000000000000000000000000000000000000000000000000000007",
                    "0x0000000000000000000000000000000000000000000000000000000000000008"
                ],
            };
            const dummyAccountProof = "0x112233445566778899";
            
            // TODO: We should process proof parsing errors better.
            await expect(minaPlaceholderVerifierIF.verifyAccountState(accountData, "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", 
                dummyAccountProof,
                params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000}
            )).to.be.reverted;
        });
    })
})
