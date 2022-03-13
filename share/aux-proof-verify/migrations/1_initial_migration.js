var Migrations = artifacts.require("migrations.sol");

module.exports = function(deployer) {
  deployer.deploy(Migrations);
};
