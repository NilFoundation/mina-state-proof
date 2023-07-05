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

        // For proof 1
        let base_params = loadParamsFromFile(path.resolve(__dirname, "./data/verifier_params_state_base.json"));
        params['init_params'][1] = base_params.init_params;
        params['columns_rotations'][0] = base_params.columns_rotations;

        // For proof 2
        let scalar_params = loadParamsFromFile(path.resolve(__dirname, "./data/verifier_params_state_scalar.json"));
        params['init_params'][2] = scalar_params.init_params;
        params['columns_rotations'][1] = scalar_params.columns_rotations;

        return params;
    }

    function getVerifierParamsAccount() {
        let account_path_params = loadParamsFromFile(path.resolve(__dirname, './data/verifier_params_account.json'));
        account_path_params['proof'] = fs.readFileSync(path.resolve(__dirname, "./data/proof_account.bin"), 'utf8');
        return account_path_params;
    }

    describe('Ledger Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await expect(minaPlaceholderVerifierIF.verifyLedgerState("jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                params['proof'], params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidated");
        });

        it("Should update and store proof ", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await minaPlaceholderVerifierIF.updateLedgerProof(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                params['proof'], params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000})
        });

        it("Should validate previously updated & stored correct proof ", async function () {
            let params = getVerifierParams();
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.isValidatedLedgerHash("jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", {gasLimit: 30_500_000})).to.equal(true);
        });
    })

    describe('Account Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            let params_state = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let ledger_hash = 'jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB';
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await minaPlaceholderVerifierIF.updateLedgerProof(
                ledger_hash,
                params_state['proof'], params_state['init_params'], params_state['columns_rotations'],
                {gasLimit: 30_500_000})


            let params_account = getVerifierParamsAccount();

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

            let inputProof = params_account['proof'];
            inputProof = inputProof.substring(2);
            let hexlifiedExtension = ethers.utils.hexlify(Buffer.from(ledger_hash));
            let extendedProof = hexlifiedExtension + inputProof;

            await expect(minaPlaceholderVerifierIF.verifyAccountState(accountData, ledger_hash, extendedProof,
                params_account['init_params'], params_account['columns_rotations'],{gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF,'AccountProofValidated');
        });
    })

    describe("Ledger Proof - Failures", function () {
        it("Should emit event on incorrect proof validation", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture'])
            params['proof'] = '0x4554480000000000000000000000000000000000000000000000000000000000'
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await expect(minaPlaceholderVerifierIF.verifyLedgerState(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                params['proof'], params['init_params'], params['columns_rotations'],
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
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", params['proof'], params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidationFailed");
        });

        it("Should fail for incorrect hash", async function () {
            let params = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture'])
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.verifyLedgerState(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", params['proof'], params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000})
            ).to.emit(minaPlaceholderVerifierIF, "InvalidLedgerHash");
        });
    })

    describe('Account Proof - Failures', function () {
        it("Should reject invalid ledger hash", async function () {
            let params_state = getVerifierParams();
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let ledger_hash = 'jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB';
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await minaPlaceholderVerifierIF.updateLedgerProof(
                ledger_hash,
                params_state['proof'], params_state['init_params'], params_state['columns_rotations'],
                {gasLimit: 30_500_000})


            let params_account = getVerifierParamsAccount();

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

            let inputProof = params_account['proof'];
            inputProof = inputProof.substring(2);
            let hexlifiedExtension = ethers.utils.hexlify(Buffer.from(ledger_hash));
            let extendedProof = hexlifiedExtension + inputProof;
            let invalid_ledger_hash  = "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcd"

            await expect(minaPlaceholderVerifierIF.verifyAccountState(accountData, invalid_ledger_hash, extendedProof,
                params_account['init_params'], params_account['columns_rotations'],{gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF,'AccountProofValidationFailed');
        });
    })
})
