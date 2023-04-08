# In-EVM Mina State Verification

This repository contains In-EVM Mina State verification project. 

## Dependencies

- [Hardhat](https://hardhat.org/)
- [nodejs](https://nodejs.org/en/) >= 16.0
- [Ganache CLI](https://github.com/trufflesuite/ganache)

## Compile 
```
npx hardhat compile
```

## Test
```
npx hardhat test #Execute tests
REPORT_GAS=true npx hardhat test # Test with gas reporting
```

## Deploy

Launch ganache using the following
```
ganache-cli -l 900000000 -m 'test test test test test test test test test test test junk' -g 20000 --verbose
```
 
To deploy to test environment (ex: Ganache)
```
npx hardhat deploy  --network ganache 
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
--network ganache
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
--network ganache
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
}

```
See `examples/data/account_data.json` for examples.

## Community

Issue reports are preferred to be done with Github Issues in here: https://github.com/nilfoundation/evm-mina-verification/issues.

Forum-alike discussion topics are better to be done with Discussions section in here: https://github.com/NilFoundation/evm-mina-verification/discussions

Usage and development questions a preferred to be asked in a Telegram chat: https://t.me/nilfoundation
