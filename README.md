# In-EVM Mina State Verification

This repository contains In-EVM Mina State verification. In particular:

1. A program `aux-proof-gen` that takes as input a Mina blockchain-state and associated Pickles SNARK and produces an auxiliary proof. 
2. An in-EVM application logic `aux-proof-verify` that has an internal state corresponding to the Mina protocol state, and which can be set to a new state only if one provides an auxiliary proof that verifies.
3. A high-level description of the implemented auxiliary proof system.