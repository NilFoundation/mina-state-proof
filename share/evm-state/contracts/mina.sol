pragma solidity ^0.8.0;

import "./state.sol";
import "./mina_state.sol";

contract mina {
    struct account {
        uint256 account;
        uint256[] values;
    }

    constructor() public {

    }

    state.protocol p;

    mapping(uint256 => account) mina_accounts;
    mapping(uint256 => bool) mina_account_inclusion_proofs;
    mapping(uint256 => bool) checklist;

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
        mina_state ver_lib = mina_state(address(0x58dF6763A14BC13B2D26e6dfe6DC7eAcBe986711));
        if (ver_lib.verify(blob, init_params, columns_rotations)) {
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