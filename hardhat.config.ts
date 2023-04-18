
require("@nomicfoundation/hardhat-toolbox");
require("@nomiclabs/hardhat-ethers");
require("hardhat-deploy");
require('hardhat-deploy-ethers')
require("hardhat-contract-sizer");

import './tasks/mina-validate-proof-task'

const SEPOLIA_PRIVATE_KEY="SEPOLIA_PRIVATE_KEY"
const SEPOLIA_ALCHEMY_KEY="SEPOLIA_ALCHEMY_KEY"
const ETHERSCAN_KEY = "ETHERSCAN_KEY"

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.18",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
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
    // sepolia: {
    //   url: `https://eth-sepolia.g.alchemy.com/v2/${SEPOLIA_ALCHEMY_KEY}`,
    //   accounts: [SEPOLIA_PRIVATE_KEY]
    // },
    ganache: {
      blockGasLimit: 100_000_000,
      url: "http://127.0.0.1:8545",
    }
  },
  etherscan: {
    apiKey: ETHERSCAN_KEY,
  },
  allowUnlimitedContractSize:true
};
