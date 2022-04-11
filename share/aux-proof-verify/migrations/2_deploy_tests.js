const TestMerkleProofVerifier = artifacts.require("TestMerkleProofVerifier");
const TestUnifiedAdditionComponent = artifacts.require("TestUnifiedAdditionComponent");
const TestPoseidonComponent = artifacts.require("TestPoseidonComponent");
const TestRedshiftVerifierUnifiedAddition = artifacts.require("TestRedshiftVerifierUnifiedAddition");
const TestRedshiftVerifierPoseidon = artifacts.require("TestRedshiftVerifierPoseidon");

module.exports = function (deployer) {
  deployer.deploy(TestMerkleProofVerifier);
  deployer.deploy(TestUnifiedAdditionComponent);
  deployer.deploy(TestPoseidonComponent);
  deployer.deploy(TestRedshiftVerifierUnifiedAddition);
  deployer.deploy(TestRedshiftVerifierPoseidon);
};
