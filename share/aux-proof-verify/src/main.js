const web3 = require('web3');
const bip39 = require('bip39');
const {hdkey} = require('ethereumjs-wallet');
const fs = require('fs');

const mnemonic = fs.readFileSync(".secret").toString().trim();
const count = 5;

function generateAddressesFromSeed(mnemonic, count) {
    let seed = bip39.mnemonicToSeedSync(mnemonic);
    let hdwallet = hdkey.fromMasterSeed(seed);
    let wallet_hdpath = "m/44'/60'/0'/0/";

    let accounts = [];
    for (let i = 0; i < count; i++) {
        let wallet = hdwallet.derivePath(wallet_hdpath + i).getWallet();
        let address = "0x" + wallet.getAddress().toString("hex");
        let privateKey = wallet.getPrivateKey().toString("hex");
        accounts.push({address: address, privateKey: privateKey});
    }
    return accounts;
}

function sendProof(address, abi, proof) {
    var contract = new web3.eth.Contract(abi, address);

    contract.methods.verify(proof).send({from: generateAddressesFromSeed(mnemonic, count)}, function (error, transactionHash) {

    });
}

function estimateGas(address, abi, proof) {
    var contract = new web3.eth.Contract(abi, address);

    contract.methods.verify(proof).estimateGas({gas: 5000000}, function (error, gasAmount) {
        if (gasAmount === 5000000) {
            console.log('Method ran out of gas');
        }
    });
}

module.exports = {generateAddressesFromSeed, sendProof, estimateGas};