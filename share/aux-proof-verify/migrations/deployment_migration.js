const verification_keys = artifacts.require("verification_keys");
const verifier = artifacts.require("verifier");

module.exports = function (deployer) {
  deployer.deploy(verification_keys);
  deployer.link(verification_keys, verifier);
  deployer.deploy(verifier);
};