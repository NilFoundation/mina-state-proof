const BN = require('bn.js');
const RedshiftVerifier = artifacts.require("TestRedshiftVerifierUnifiedAddition");

module.exports = function (deployer) {
  deployer.deploy(RedshiftVerifier);
};