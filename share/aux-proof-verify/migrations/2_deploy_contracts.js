const verification_keys = artifacts.require("verification_keys");
const merkle_verifier = artifacts.require("merkle_verifier");
const lpc_verifier = artifacts.require("lpc_verifier");

module.exports = function (deployer) {
  deployer.deploy(merkle_verifier);
  deployer.deploy(verification_keys);
  deployer.link(merkle_verifier, lpc_verifier);
  deployer.link(verification_keys, lpc_verifier);
  deployer.deploy(lpc_verifier);
};