# In-EVM Mina State Verification

[![Discord](https://img.shields.io/discord/969303013749579846.svg?logo=discord&style=flat-square)](https://discord.gg/KmTAEjbmM3)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=flat-square&logo=telegram&logoColor=dark)](https://t.me/nilfoundation)
[![Twitter](https://img.shields.io/twitter/follow/nil_foundation)](https://twitter.com/nil_foundation)

This repository contains In-EVM Mina State verification project.

## Dependencies

- [Hardhat](https://hardhat.org/)
- [nodejs](https://nodejs.org/en/) >= 16.0


## Clone
```
git clone git@github.com:NilFoundation/mina-state-proof.git
cd mina-state-proof
```

## Install dependency packages
```
npm i
```

## Compile contracts
```
npx hardhat compile
```

## Test
```
npx hardhat test #Execute tests
REPORT_GAS=true npx hardhat test # Test with gas reporting
```

## Deploy

Launch a local-network using the following
```
npx hardhat node
```

To deploy to test environment (ex: Ganache)
```
npx hardhat deploy  --network localhost 
```

Hardhat re-uses old deployments, to force re-deploy add the `--reset` flag above

## Usage

Below are two tasks that execute flows to validate the ledger state and validate the account state.
Please note, these work against the above deployment, hence, you must run the deployment before executing
the following.

### Validate Ledger State
```
npx hardhat validate_ledger_state --proof ./test/data/proof_v.data \ 
--ledger jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB \  
--network localhost
```
Inputs
- _proof : File path with the full Mina ledger state proof retrieved from proof market._
- _ledger: This is the hash of the ledger which this proof attests._
- _network: Network to run this task against._


### Validate Account State
```
npx hardhat validate_account_state --proof dummyFlag \  
--state ./examples/data/account_data.json \
--ledger jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB \ 
--network localhost
```
Inputs
- _proof : File path of the account state proof retrieved from the proof market._
- _state : File path of the account state which the above proof attests to._
- _ledger: Hash of the ledger against which the account state is validated._
- _network: Network to run this task against._

### Account state file structure

```JSON
{
  "public_key" : public key of zkApp/User Account,
  "balance" : {
    "liquid" : Unlocked balance in MINA  ,
    "locked" : Locked/Staked balance in MINA 
  },
  "state": 8 byte state of zkApp/user account
  "proof_extension": Ledger hash for account state        
}

```
See `examples/data/account_data.json` for examples.

## Community

Issue reports are preferred to be done with Github Issues in here: https://github.com/nilfoundation/mina-state-proof/issues.

Forum-alike discussion topics are better to be done with Discussions section in here: https://github.com/NilFoundation/mina-state-proof/discussions

Usage and development questions are preferred to be asked in a Telegram chat: https://t.me/nilfoundation or in Discord (https://discord.gg/KmTAEjbmM3)