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
TODO

## Usage
TODO

ganache-cli -l 900000000 -m 'test test test test test test test test test test test junk' -g 20000 --verbose

npx hardhat --network ganache validate_account_state --proof f --publickey B62qre3ersHfzQckNuibViWTGyyKwZseztqrjPjBv6SQF384Rg6ESAy --balance 5000 --state "0x0000000000000000000000000000000000000000000000000000000000000001,0x0000000000000000000000000000000000000000000000000000000000000002,0x0000000000000000000000000000000000000000000000000000000000000003,0x0000000000000000000000000000000000000000000000000000000000000004,0x0000000000000000000000000000000000000000000000000000000000000005,0x0000000000000000000000000000000000000000000000000000000000000006,0x0000000000000000000000000000000000000000000000000000000000000007,0x0000000000000000000000000000000000000000000000000000000000000008"

npx hardhat validate_ledger_state --proof /home/hgedia/Development/nil/mina-state-proof/test/data/proof_v.data  --network ganache 