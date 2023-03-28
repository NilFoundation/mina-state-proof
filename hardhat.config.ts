
require("@nomicfoundation/hardhat-toolbox");
require("@nomiclabs/hardhat-ethers");
require("hardhat-deploy");
require('hardhat-deploy-ethers')
import './tasks/mina-validate-proof-task'



/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.18",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1200,
      },
    },
  },
  namedAccounts: {
    deployer: 0,
  },
  networks: {
    hardhat: {
      blockGasLimit: 100_000_000,
    },
    sepolia: {
      blockGasLimit: 100_000_000,
      url : "0"
    },
    ganache: {
      url: "http://127.0.0.1:8545",
      // accounts: [privateKey1, privateKey2, ...]
    }
  }
};
