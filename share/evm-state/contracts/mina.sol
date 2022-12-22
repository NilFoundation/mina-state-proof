pragma solidity ^0.8.0;

import "@nilfoundation/evm-placeholder-verification/verifier.sol";

import "./state.sol";
import "./mina_state.sol";

contract mina {
    struct account {
        uint256 account;
        uint256[] values;
    }

    IVerifier verifier;
    state.protocol p;

    mapping(uint256 => account) mina_accounts;
    mapping(uint256 => bool) mina_account_inclusion_proofs;
    mapping(uint256 => bool) checklist;

    constructor(address verifier) public {
        verifier = verifier;
    }

    function poseidon_hash(uint256 input) public view returns (uint256) {
        return 0;
    }

    function set_state(state.protocol memory _p) public {
        p = _p;
    }

    function set_inclusion_proof(
        uint256 acc,
        bytes calldata blob,
        uint256[] calldata init_params,
        int256[][] calldata columns_rotations
    ) public {
        if (verifier.verify(blob, init_params, columns_rotations)) {
            mina_account_inclusion_proofs[acc] = true;
        }
    }

    function set(account memory acc) public {
        if (mina_account_inclusion_proofs[acc.account]) {
            if (checklist[poseidon_hash(acc.account)]) {
                mina_accounts[poseidon_hash(acc.account)] = acc;
            }
        }
    }

    function get(uint256 public_key) public returns (bool checked) {
        return mina_account_inclusion_proofs[public_key];
    }
}