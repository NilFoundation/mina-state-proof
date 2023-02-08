// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

import "./constants.sol";
import "./consensus.sol";

library mina_state {
    struct acc_address {
        uint256 account_address;
        bool signed;
    }

    struct consensus_mina {
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

    struct mina_protocol_body {
        /// Genesis protocol state hash (used for hardforks)
        uint256 genesis_state_hash;
        /// Ledger related state
        commitlog blockchain_state;
        /// Consensus related state
        consensus_mina consensus_state;
        /// Consensus constants
        consensus_mina constants;
    }

    /// This structure can be thought of like the block header. It contains the most essential information of a block.
    struct base_protocol {
        /// Commitment to previous block (hash of previous protocol state hash and body hash)
        uint256 previous_state_hash;
        /// The body of the mina protocol state
        mina_protocol_body body;
    }
}
