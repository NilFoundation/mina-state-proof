import { isReady,Mina, PrivateKey, shutdown } from 'snarkyjs';

await isReady;

const zkAppPrivateKey = PrivateKey.random();
const zkAppPublicKey = zkAppPrivateKey.toPublicKey();

const userPrivateKey = PrivateKey.random();
const userPublicKey = userPrivateKey.toPublicKey();

console.log("--------WARNING: UNSECURE KEYS DO NOT USE IN PRODUCTION ENV----------------\n")
console.log("--------------------------------------------------------------------------")
console.log(`zkApp private key: ${zkAppPrivateKey.toBase58()}`);
console.log(`zkApp public key : ${zkAppPublicKey.toBase58()}`);
console.log("--------------------------------------------------------------------------")
console.log(`user private key : ${userPrivateKey.toBase58()}`);
console.log(`user public key  : ${userPublicKey.toBase58()}`);
console.log("--------------------------------------------------------------------------")

process.exit(0);