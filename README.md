# In-EVM Mina State Verification

This repository contains In-EVM Mina State verification project. In particular:

1. A program `aux-proof-gen` that takes as input a Mina blockchain-state and associated Pickles SNARK and produces an auxiliary proof. 
2. An in-EVM application logic `aux-proof-verify` that has an internal state corresponding to the Mina protocol state, and which can be set to a new state only if one provides an auxiliary proof that verifies.
3. A high-level description of the implemented auxiliary proof system.

## Documentation

Project documentation, circuit definitions, API references etc can be found at https://verify.mina.nil.foundation/docs.

## Auxiliary Proof Generator (`aux-proof-gen`)

Auxiliary proof generator is UNIX-style application taking Mina Protocol state as an input and producing auxiliary proof as an output. 

The generator prototype is implemented in C++ and uses =nil; Crypto3 C++ Cryptography Suite (https://github.com/nilfoundation/crypto3) for cryptographic primitives definition.

### Dependencies

Libraries requirements are as follows:
* Boost (https://boost.org) (>= 1.76)

Compiler/environment requirements are as follows:
* CMake (https://cmake.org) (>= 3.13)
* GCC (>= 10.3) / Clang (>= 9.0.0) / AppleClang (>= 11.0.0)

### Building

#### Native

`mkdir build && cd build && cmake .. && make aux-proof-gen`

### Usage

`bin/aux-proof-gen/aux-proof-gen ../share/mina/genesis_proof_*`

### Tests

`make zk_lpc_test && make zk_fri_test`

### Benchmarks

`make zk_lpc_performance_test`

## Community

Issue reports are preferred to be done with Github Issues in here: https://github.com/nilfoundation/evm-mina-verification/issues.

Forum-alike discussion topics are better to be done with Discussions section in here: https://github.com/NilFoundation/evm-mina-verification/discussions

Usage and development questions a preferred to be asked in a Telegram chat: https://t.me/nilcrypto3
