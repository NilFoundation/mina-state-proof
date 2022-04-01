const TestUnifiedAdditionComponent = artifacts.require("TestUnifiedAdditionComponent");
const TestPoseidonComponent = artifacts.require("TestPoseidonComponent");
const TestRedshiftVerifierUnifiedAddition = artifacts.require("TestRedshiftVerifierUnifiedAddition");

module.exports = function (deployer) {
  deployer.deploy(TestUnifiedAdditionComponent);
  deployer.deploy(TestPoseidonComponent);
  deployer.deploy(TestRedshiftVerifierUnifiedAddition);
};
