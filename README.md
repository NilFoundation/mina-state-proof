# Mina State proof verification in EVM

This repository presents the solidity smart contracts required to verify Mina ledger proof in EVM. 
The repository uses Hardhat as development environment for compilation, testing and deployment tasks.

## Dependencies

- [Hardhat](https://hardhat.org/)
- [nodejs](https://nodejs.org/en/) >= 16.0

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

Launch ganche using the following
```
ganache-cli -l 900000000 -m 'test test test test test test test test test test test junk' -g 20000 --verbose
```
 
To deploy to test environment (ex: Ganache)
```
npx hardhat deploy  --network ganache 
```

Hardhat re-uses old deployments, to force re-deploy add the `--reset` flag above

## Usage

Below two tasks execute flows to validate ledger state and validate account state. 
Please note , these work against the above delpoyment, hence , you must run the deploy before
executing the following.

### Validate Ledger State
```
npx hardhat validate_ledger_state --proof ./test/data/proof_v.data --ledger jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB  --network ganache
```
Inputs
- _proof : This is file path with the full mina ledger state 
proof retrieved from proof market._
- _ledger: This is the hash of the ledger which this proof attests._
- _network: Network to run this task against_


### Validate Account State
```
npx hardhat validate_account_state --proof dummyFlag  --state ./examples/data/account_data.json --ledger jwYPLbRQa4X86tSJs1aTzusf3TNdVTj58oyWJQB132sEGUtKHcB --network ganache
```
Inputs
- _proof : This is file path of the account state proof retrieved from proof market_
- _state : This the file path of the account state which the above proof attests to._
- _ledger: This is the hash of the ledger against which the account state is validated._
- _network: Network to run this task against_

### Account state file structure

```
{
  "public_key" : public key of zkApp/User Account,
  "balance" : {
    "liquid" : Unlocked balance in MINA  ,
    "locked" : Locked/Staked balance in MINA 
  },
  "state": 8 byte state of zkApp/user account
}

```
See `examples/data/account_data.json` for example contents.