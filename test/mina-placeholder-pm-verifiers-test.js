
const {expect} = require("chai");
const hre = require('hardhat')
const path = require("path");
const { getStateVerifierParams, getAccountVerifierParams, getFileContents} = require("./utils/utils")

const stateProofFile = path.resolve(__dirname, "./data/proof_state.bin");
const baseParamsFile = path.resolve(__dirname, "../circuits/params/verifier_params_state_base.json");
const scalarParamsFile = path.resolve(__dirname, "../circuits/params/verifier_params_state_scalar.json");
const accountParamsFile = path.resolve(__dirname, '../circuits/params/verifier_params_account.json');
const accountProofFile = path.resolve(__dirname, "./data/proof_account.bin");

describe('PM - Mina state and account proofs validation tests', function () {
    const {deployments } = hre;
    describe('Ledger Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            let proof = getFileContents(stateProofFile);
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let minaStatePMVerifier = await ethers.getContract('MinaStateVerifier');
            let minaStatePMVerifierIF = await ethers.getContractAt(
                "ICustomVerifier",
                minaStatePMVerifier.address
            );
            let public_input = [[1,2,3]];
            let result = await minaStatePMVerifierIF.verify(
                proof,
                public_input,
                {gasLimit: 30_500_000}
            )
            expect(result).to.equal(true);
        });
    })

    describe('Account Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let minaAccountPMVerifier = await ethers.getContract('AccountPathVerifier');
            let minaAccountPMVerifierIF = await ethers.getContractAt(
                "ICustomVerifier",
                minaAccountPMVerifier.address
            );
            let proof = getFileContents(accountProofFile);
            let public_input = [[1,2,3]];
            let result = await minaAccountPMVerifierIF.verify(
                proof,
                public_input,
                {gasLimit: 30_500_000}
            );
            expect(result).to.equal(true);
        });
    })
})
