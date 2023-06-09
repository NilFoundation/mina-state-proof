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
        params['public_inputs'][0] = [];

        // For proof 2
        let scalar_params = loadParamsFromFile(path.resolve(__dirname, "./data/verifier_params_state_scalar.json"));
        params['init_params'][2] = scalar_params.init_params;
        params['columns_rotations'][1] = scalar_params.columns_rotations;
        params['public_inputs'][1] = [];

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
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

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
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await minaPlaceholderVerifierIF.updateLedgerProof(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000})
        });

        it("Should validate previously updated & stored correct proof ", async function () {
            let params = getVerifierParams();
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.isValidatedLedgerHash("jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", {gasLimit: 30_500_000})).to.equal(true);
        });
    })

    describe.skip('Account Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            let params = getVerifierParamsAccount();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await minaPlaceholderVerifierIF.updateLedgerProof("jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000}
            )

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
            await minaPlaceholderVerifierIF.verifyAccountState(accountData, "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", params['proof'],
                params['init_params'], params['columns_rotations'], params['public_inputs'],
            );
        });
    })

    describe("Ledger Proof - Failures", function () {
        it("Should emit event on incorrect proof validation", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture'])
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

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
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

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
            let mina_base_gate_argument_contract = await ethers.getContract('mina_base_split_gen');
            let mina_scalar_gate_argument_contract = await ethers.getContract('mina_scalar_split_gen');
            let placeholder_verifier_contract = await ethers.getContract('PlaceholderVerifier');

            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.verifyLedgerState(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", 
                params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs'],
                {gasLimit: 30_500_000})
            ).to.emit(minaPlaceholderVerifierIF, "InvalidLedgerHash");
        });
    })

    describe.skip('Account Proof - Failures', function () {
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
            const dummyAccountProof = "0x112233445566778899";
            await expect(await minaPlaceholderVerifierIF.verifyAccountState(
                accountData, "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", params['proof'], params['init_params'], params['columns_rotations'], params['public_inputs']))
                .to.emit(minaPlaceholderVerifierIF, "InvalidLedgerHash");
            ;
        });
    })
})
