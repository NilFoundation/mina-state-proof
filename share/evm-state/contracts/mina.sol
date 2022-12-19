pragma solidity ^0.8.0;

import "./state.sol";

contract mina {
    struct account {
        uint256 account;
        uint256[] values;
    }

    function mina() {

    }

    state.protocol p;

    mapping(uint256 => account) mina_accounts;
    mapping(uint256 => uint256) mina_account_inclusion_proofs;
    mapping(uint256 => bool) checklist;

    function set_state(state.protocol p) {

    }

    function set_inclusion_proof(uint256 acc, bytes calldata blob,
        uint256[][] calldata init_params,
        int256[][][] calldata columns_rotations) {
        if (verify(calldata, init_params, column_rotations)) {
            mina_account_inclusion_proofs[acc] = true;
        }
    }

    function set(account acc) {
        if (mina_account_inclusion_proofs[acc]) {
            if (checklist[poseidon_hash(acc)]) {
                mina_accounts[poseidon_hash(acc)] = acc;
            }
        }
    }

    function get(uint256 public_key) returns (uint256[] values) {

    }
}