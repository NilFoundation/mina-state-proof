const TestMerkleProofVerifier = artifacts.require("TestMerkleProofVerifier");
const TestFriVerifier = artifacts.require("TestFriVerifier");
const TestLpcVerifier = artifacts.require("TestLpcVerifier");
const TestPermutationArgument = artifacts.require("TestPermutationArgument");
const TestPermutationArgumentCalldataInput = artifacts.require("TestPermutationArgumentCalldataInput");
const TestUnifiedAdditionComponent = artifacts.require("TestUnifiedAdditionComponent");
const TestUnifiedAdditionComponentCalldataInput = artifacts.require("TestUnifiedAdditionComponentCalldataInput");
const TestPoseidonComponent = artifacts.require("TestPoseidonComponent");
const TestRedshiftVerifierUnifiedAddition = artifacts.require("TestRedshiftVerifierUnifiedAddition");
const TestRedshiftVerifierUnifiedAdditionCalldataInput = artifacts.require("TestRedshiftVerifierUnifiedAdditionCalldataInput");
const TestRedshiftVerifierPoseidon = artifacts.require("TestRedshiftVerifierPoseidon");

module.exports = function (deployer) {
  deployer.deploy(TestMerkleProofVerifier);
  deployer.deploy(TestFriVerifier);
  deployer.deploy(TestLpcVerifier);
  deployer.deploy(TestPermutationArgument);
  deployer.deploy(TestPermutationArgumentCalldataInput);
  deployer.deploy(TestUnifiedAdditionComponent);
  deployer.deploy(TestUnifiedAdditionComponentCalldataInput);
  deployer.deploy(TestPoseidonComponent);
  deployer.deploy(TestRedshiftVerifierUnifiedAddition);
  deployer.deploy(TestRedshiftVerifierUnifiedAdditionCalldataInput);
  deployer.deploy(TestRedshiftVerifierPoseidon);
};
