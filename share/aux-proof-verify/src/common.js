const Web3 = require('web3');
const bip39 = require('bip39');
const {hdkey} = require('ethereumjs-wallet');
const fs = require('fs');

const host = "https://ropsten.infura.io/v3/6f3d827e1a7241859cf304c63a4f3167"
const mnemonic = fs.readFileSync(".secret").toString().trim();
const count = 1;

const web3 = new Web3(new Web3.providers.HttpProvider(
    host
));

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
    var result = false;

    return contract.methods.verify(proof).call({from: generateAddressesFromSeed(mnemonic, count)[0].address}).then(res => {
        return true
    }).catch(res => {
        return false
    });
}

function estimateGas(address, abi, proof) {
    var contract = new web3.eth.Contract(abi, address);

    contract.methods.verify(proof).estimateGas({gas: 5000000}, function (error, gasAmount) {
        if (gasAmount === 5000000) {
            console.log('Method ran out of gas');
        } else {
            console.log(gasAmount);
        }
    });
}

module.exports = {generateAddressesFromSeed, sendProof, estimateGas};
