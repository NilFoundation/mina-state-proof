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
const {loadParamsFromFile, getVerifierParams, getVerifierParamsAccount, getFileContents} = require("./utils/utils")

const stateProofFile = path.resolve(__dirname, "./data/proof_state.bin");
const baseParamsFile = path.resolve(__dirname, "./data/verifier_params_state_base.json");
const scalarParamsFile = path.resolve(__dirname, "./data/verifier_params_state_scalar.json");
const accountParamsFile = path.resolve(__dirname, './data/verifier_params_account.json');
const accountProofFile = path.resolve(__dirname, "./data/proof_account.bin");
//let proof = getFileContents(stateProofFile);
/* global BigInt */

describe('Mina state proof validation tests', function () {
    const {deployments, getNamedAccounts} = hre;
    const {deploy} = deployments;
    describe('Ledger Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            let params = getVerifierParams(baseParamsFile,scalarParamsFile);
            let proof = getFileContents(stateProofFile);
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await expect(minaPlaceholderVerifierIF.verifyLedgerState("jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                proof, params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidated");
        });

        it("Should update and store proof ", async function () {
            let params = getVerifierParams(baseParamsFile,scalarParamsFile);
            let proof = getFileContents(stateProofFile);
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await minaPlaceholderVerifierIF.updateLedgerProof(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
               proof, params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000})
        });

        it("Should validate previously updated & stored correct proof ", async function () {
            let params = getVerifierParams(baseParamsFile,scalarParamsFile);
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.isValidatedLedgerHash("jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", {gasLimit: 30_500_000})).to.equal(true);
        });
    })

    describe('Account Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            let params_state = getVerifierParams(baseParamsFile,scalarParamsFile);
            let stateProof = getFileContents(stateProofFile);
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let ledger_hash = 'jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB';
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await minaPlaceholderVerifierIF.updateLedgerProof(
                ledger_hash,
                stateProof, params_state['init_params'], params_state['columns_rotations'],
                {gasLimit: 30_500_000})


            let params_account = getVerifierParamsAccount(accountParamsFile);
            let accountProof = getFileContents(accountProofFile);

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


            let inputProof = accountProof.substring(2);
            let hexlifiedExtension = ethers.utils.hexlify(Buffer.from(ledger_hash));
            let extendedProof = hexlifiedExtension + inputProof;

            await expect(minaPlaceholderVerifierIF.verifyAccountState(accountData, ledger_hash, extendedProof,
                params_account['init_params'], params_account['columns_rotations'],{gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF,'AccountProofValidated');
        });
    })

    describe("Ledger Proof - Failures", function () {
        it("Should emit event on incorrect proof validation", async function () {
            let params = getVerifierParams(baseParamsFile,scalarParamsFile);
            await deployments.fixture(['minaPlaceholderVerifierFixture'])
            let invalidProof = '0x4554480000000000000000000000000000000000000000000000000000000000'
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await expect(minaPlaceholderVerifierIF.verifyLedgerState(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB",
                invalidProof, params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidationFailed");
        });

        it("Should fail to update and store incorrect proof ", async function () {
            let params = getVerifierParams(baseParamsFile,scalarParamsFile);
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let invalidProof = '0x4554480000000000000000000000000000000000000000000000000000000000'
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.updateLedgerProof(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", invalidProof, params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF, "LedgerProofValidationFailed");
        });

        it("Should fail for incorrect hash", async function () {
            let params = getVerifierParams(baseParamsFile,scalarParamsFile);
            let proof = getFileContents(stateProofFile);
            await deployments.fixture(['minaPlaceholderVerifierFixture'])
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            expect(await minaPlaceholderVerifierIF.verifyLedgerState(
                "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB", proof, params['init_params'], params['columns_rotations'],
                {gasLimit: 30_500_000})
            ).to.emit(minaPlaceholderVerifierIF, "InvalidLedgerHash");
        });
    })

    describe('Account Proof - Failures', function () {
        it("Should reject invalid ledger hash", async function () {
            let params_state = getVerifierParams(baseParamsFile,scalarParamsFile);
            let proof = getFileContents(stateProofFile);
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let ledger_hash = 'jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB';
            let minaPlaceholderVerifier = await ethers.getContract('MinaState');
            let minaPlaceholderVerifierIF = await ethers.getContractAt("IMinaPlaceholderVerifier", minaPlaceholderVerifier.address);
            await minaPlaceholderVerifierIF.updateLedgerProof(
                ledger_hash,
                proof, params_state['init_params'], params_state['columns_rotations'],
                {gasLimit: 30_500_000})


            let params_account = getVerifierParamsAccount(accountParamsFile);
            let accountProof = getFileContents(accountProofFile);

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

            let inputProof = accountProof.substring(2);
            let hexlifiedExtension = ethers.utils.hexlify(Buffer.from(ledger_hash));
            let extendedProof = hexlifiedExtension + inputProof;
            let invalid_ledger_hash  = "jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcd"

            await expect(minaPlaceholderVerifierIF.verifyAccountState(accountData, invalid_ledger_hash, extendedProof,
                params_account['init_params'], params_account['columns_rotations'],{gasLimit: 30_500_000}
            )).to.emit(minaPlaceholderVerifierIF,'AccountProofValidationFailed');
        });
    })
})
