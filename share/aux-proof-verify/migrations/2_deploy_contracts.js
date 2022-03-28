const BN = require('bn.js');
const RedshiftVerifierLib = artifacts.require("redshift_verifier");
const RedshiftVerifier = artifacts.require("RedshiftVerifier");

module.exports = function (deployer) {
  deployer.deploy(RedshiftVerifierLib);
  deployer.link(RedshiftVerifierLib, RedshiftVerifier);
  deployer.deploy(RedshiftVerifier, new BN('40000000000000000000000000000000224698fc094cf91b992d30ed00000001', 16), 1, 3, 1, 2, 4, new BN('24760239192664116622385963963284001971067308018068707868888628426778644166363', 10), 13);
};