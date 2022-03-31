const BN = require('bn.js');
const TestUnifiedAdditionComponent = artifacts.require("TestUnifiedAdditionComponent");
const TestRedshiftVerifierUnifiedAddition = artifacts.require("TestRedshiftVerifierUnifiedAddition");

module.exports = function (deployer) {
  deployer.deploy(TestUnifiedAdditionComponent);
  deployer.deploy(TestRedshiftVerifierUnifiedAddition);
};
