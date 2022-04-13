const TestMerkleProofVerifier = artifacts.require("TestMerkleProofVerifier");
const TestFriVerifier = artifacts.require("TestFriVerifier");
const TestLpcVerifier = artifacts.require("TestLpcVerifier");
const TestPermutationArgument = artifacts.require("TestPermutationArgument");
const TestUnifiedAdditionComponent = artifacts.require("TestUnifiedAdditionComponent");
const TestPoseidonComponent = artifacts.require("TestPoseidonComponent");
const TestRedshiftVerifierUnifiedAddition = artifacts.require("TestRedshiftVerifierUnifiedAddition");
const TestRedshiftVerifierPoseidon = artifacts.require("TestRedshiftVerifierPoseidon");

module.exports = function (deployer) {
  deployer.deploy(TestMerkleProofVerifier);
  deployer.deploy(TestFriVerifier);
  deployer.deploy(TestLpcVerifier);
  deployer.deploy(TestPermutationArgument);
  deployer.deploy(TestUnifiedAdditionComponent);
  deployer.deploy(TestPoseidonComponent);
  deployer.deploy(TestRedshiftVerifierUnifiedAddition);
  deployer.deploy(TestRedshiftVerifierPoseidon);
};
