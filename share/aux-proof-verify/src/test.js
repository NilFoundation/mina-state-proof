const myModule = require("./state-proof-gen.js");
const myModule2 = require('./verifyRedshiftUnifiedAddition.js');
const fs = require("fs");
const web3 = require('web3');
const bip39 = require('bip39');
const {hdkey} = require('ethereumjs-wallet');

var result = myModule.onRuntimeInitialized = () => {
    var t = myModule.ccall('example', // name of C function
        'string', // return type
        null, // argument types
        null // arguments
    );
    t = t.slice(0, -1); // remove /n from the end

    myModule2.verifyRedshiftUnifiedAddition(t);
}