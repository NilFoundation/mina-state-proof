# Mina zkApp: Add

In this example we deploy a zkApp which has 8 state variables initialized to  `1,2,3,4,5,6,7,8`
The contract has a method `update` which increments the zkApp state fields by `1,2,3,4,5,6,7,8`
each of them respectively.  
- `update#1` values changed to `2,4,6,8,10,12,14,16` 
- `update#2` values changed to `3,6,9,12,15,18,21,24`.

Configuration is set-up to be deployed on `BERKELEY` testnet.

## Dependencies
- [NodeJS 16+](https://nodejs.org/en/)
- [NPM 6](https://www.npmjs.com/)


## Setup
### Clone the repository 
```
git clone git@github.com:NilFoundation/mina-zkapp-demo.git
cd mina-zkapp-demo
```
### Install project dependencies
```
npm install -g zkapp-cli
npm i
```

### Setup keys/Fund wallet
There are two key-pairs required to deploy the zkApp to testnet
- zkApp : This keypair is for the zkApp. Located in `keys/berkeley.json`  
- User: This keypair is for user signing & calling zkApp method. Located in `keys/user.json`

User must update these files, see below to generate keypair.

#### Generate key Pair

The keypair generated with the below command should **ONLY** be used for test environments.

```
npm run build && node build/src/generateKeyPairs.js
```
This commands outputs :
```
--------WARNING: UNSECURE KEYS DO NOT USE IN PRODUCTION ENV----------------

--------------------------------------------------------------------------
zkApp private key: EKxxxxxxxxxxxxxxxxxxxxxxxxx
zkApp public key : B62xxxxxxxxxxxxxxxxxxxxxxxx
--------------------------------------------------------------------------
user private key : EKxxxxxxxxxxxxxxxxxxxxxxxxx
user public key  : B62xxxxxxxxxxxxxxxxxxxxxxxx
--------------------------------------------------------------------------
```
User should copy the 
- `zkApp` key pair to `keys/berkeley.json`
- `user` key pair to `keys/user.json`

Both wallets **must** be funded by requesting faucet funds on `BERKELEY` network here 
by providing the public key:

```
https://faucet.minaprotocol.com/
```

### Build Project
Typescript must be compiled to javascript to be executed , this is done via. 
```sh
npm run build
```
_This should be run after any changes are made to the project._

### Deploy zkApp to Berkley testnet
Once funded , this command will deploy zkApp `Add` to  `berkeley` testnet. The address of the
zkApp is the public key defined in `keys\berkeley.json`.

```
zk deploy berkeley
```

### Call `update` on `Add` zkApp
This command will call the update method of the zkApp `Add`
```
node build/src/interact.js berkeley
```

### See updated state GraphQL

The graphQL dashboard to query `BERKELY` testnet data is located here : https://proxy.berkeley.minaexplorer.com/

The following query will fetch state for zkApp & a merkle path to the staged ledger to it.
```
query {
  account(publicKey: "ZKAPP_PUBLIC_KEY") {
    index
    balance {
      liquid
      locked
      stateHash
    }
    zkappState
    leafHash
    receiptChainHash
    merklePath {
      left,
      right
    }
  }
}

```

## Testing

```sh
npm run test
```

## License

[Apache-2.0](LICENSE)
