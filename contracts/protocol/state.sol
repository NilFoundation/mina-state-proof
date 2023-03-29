// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

import "./constants.sol";
import "./consensus.sol";

library state {
    struct signed_amount {
        uint256 amount;
        bool signed;
    }

    struct local_state_registers {
        /// TODO
        uint256 stack_frame;
        /// TODO
        uint256 call_stack;
        /// TODO
        uint256 transaction_commitment;
        /// TODO
        uint256 full_transaction_commitment;
        /// TODO
        uint64 token_id;
        /// TODO
        signed_amount excess;
        /// TODO
        uint256 ledger;
        /// TODO
        bool success;
        /// TODO
        uint32 party_index;
        /// TODO
        uint256[] failure_status_tbl;
    }

    struct state_registers {
        /// TODO
        uint256 ledger;
        /// TODO
        uint256[] pending_coinbase_stack;
        /// TODO
        local_state_registers local_state;
    }

    struct commitlog {
        /// Hash of the proposed next state of the blockchain
        uint256 staged_ledger_hash;
        /// Hash of the genesis state
        uint256 genesis_ledger_hash;
        /// Registers
        state_registers registers;
        /// Timestamps for blocks
        uint256 timestamp;
        /// Body reference
        uint256 body_reference;
    }

    struct consensus_t {
        /// Height of block
        uint256 blockchain_length;
        /// Epoch number
        uint256 epoch_count;
        /// Minimum window density oberved on the chain
        uint256 min_window_density;
        /// Current sliding window of densities
        uint256[] sub_window_densities;
        /// Additional VRS output from leader (for seeding Random Oracle)
        uint256[] last_vrf_output;
        /// Total supply of currency
        uint256 total_currency;
        /// Current global slot number relative to the current hard fork
        consensus.global_slot curr_global_slot;
        /// Absolute global slot number since genesis
        uint256 global_slot_since_genesis;
        /// Epoch data for previous epoch
        consensus.epoch_data staking_epoch_data;
        /// Epoch data for current epoch
        consensus.epoch_data next_epoch_data;
        /// If the block has an ancestor in the same checkpoint window
        bool has_ancestor_in_same_checkpoint_window;
        /// Compressed public key of winning account
        uint256 block_stake_winner;
        /// Compressed public key of the block producer
        uint256 block_creator;
        /// Compresed public key of account receiving the block reward
        uint256 coinbase_receiver;
        /// true if block_stake_winner has no locked tokens, false otherwise
        bool supercharge_coinbase;
    }

    struct protocol_body {
        /// Genesis protocol state hash (used for hardforks)
        uint256 genesis_state_hash;
        /// Ledger related state
        commitlog blockchain_state;
        /// Consensus related state
        consensus_t consensus_state;
        /// Consensus constants
        consensus_t constants;
    }

    /// This structure can be thought of like the block header. It contains the most essential information of a block.
    struct protocol {
        /// Commitment to previous block (hash of previous protocol state hash and body hash)
        uint256 previous_state_hash;
        /// The body of the protocol state
        protocol_body body;
    }

    /// This structure stores the balance parameters of user/zkApp
    struct balance {
        // Liquid balance
        uint256 liquid;
        // Locked balance of user
        uint256 locked;
    }

    struct account_state {
        /// Public key identifier of the account (user or zkApp)
        string public_key;
        /// Balance of MINA
        balance balance;
        /// Sate of the zkApp (8 FieldElems of 32 bytes)
        bytes32[8] state;
    }
}
