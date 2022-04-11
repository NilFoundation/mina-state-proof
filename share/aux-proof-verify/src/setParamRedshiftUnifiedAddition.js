const Web3 = require('web3');
const bip39 = require('bip39');
const {hdkey} = require('ethereumjs-wallet');
const fs = require('fs');
const BN = require("bn.js");

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
        } else {
            console.log(gasAmount);
        }
    });
}

function verify_encoded(encoded, adress) {
    var tx = {
        to : adress.address,
        gasPrice: web3.utils.toHex(web3.utils.toWei('20', 'gwei')),
        gasLimit: 100000,
    }
    console.log()

    web3.eth.accounts.signTransaction(tx, adress.privateKey).then(signed => {
        web3.eth.sendSignedTransaction(signed.rawTransaction).on('receipt', console.log)
    });
}

const web3 = new Web3(new Web3.providers.HttpProvider(
    "https://ropsten.infura.io/v3/6f3d827e1a7241859cf304c63a4f3167"
));

web3.eth.net.isListening()
    .then(() => console.log('web3 is connected'))
    .catch(e => console.log('Wow. Something went wrong'));
const contract_data = JSON.parse(
    fs.readFileSync("TestRedshiftVerifierUnifiedAddition.json")
);


var adress = generateAddressesFromSeed(mnemonic, 1);

console.log(adress[0].address)
web3.eth.getBalance(adress[0].address).then(console.log)

// var contract = new web3.eth.Contract(contract_data.abi, "0x2ab4343f34cd01088af926b436bd7043e7945fbe");
// new
var contract = new web3.eth.Contract(contract_data.abi, "0x8EFde6959Bc5CA35A8C26221de6aa8d732877df9");


verify_encoded(contract.methods.set_q([0, 0, 1]).encodeABI(), adress[0]);

verify_encoded(contract.methods.set_initial_params(
    new BN('40000000000000000000000000000000224698fc094cf91b992d30ed00000001', 16),
    1,
    3,
    1,
    2,
    4,
    new BN('24760239192664116622385963963284001971067308018068707868888628426778644166363', 10),
    13
).encodeABI(), adress[0]);

verify_encoded(contract.methods.set_D_omegas([new BN('24760239192664116622385963963284001971067308018068707868888628426778644166363', 10),]).encodeABI(), adress[0]);

for (var i = 0; i < 13; i++) {
    verify_encoded(contract.methods.set_column_rotations([0,], i).encodeABI(), adress[0]);
}

verify_encoded(contract.methods.set_column_rotations([0,], 1).encodeABI(), adress[0]);
