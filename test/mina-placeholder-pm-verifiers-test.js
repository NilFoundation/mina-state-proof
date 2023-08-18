
const {expect} = require("chai");
const hre = require('hardhat')
const path = require("path");
const { getFileContents} = require("./utils/utils")

const stateProofFile = path.resolve(__dirname, "./data/proof_ledger.bin");
const accountProofFile = path.resolve(__dirname, "./data/proof_account.bin");

describe('Proof Market verifiers - Mina state and account proofs validation tests', function () {
    const {deployments } = hre;
    describe('Ledger Proof - Success', function () {
        it("Should validate correct proof ", async function () {
            let proof = getFileContents(stateProofFile);
            await deployments.fixture(['minaPlaceholderVerifierFixture']);
            let minaStatePMVerifier = await ethers.getContract('MinaStateVerifier');
            let minaStatePMVerifierIF = await ethers.getContractAt(
                "IProofMarketVerifier",
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
                "IProofMarketVerifier",
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
