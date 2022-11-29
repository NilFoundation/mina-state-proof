// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

library consensus {
    struct global_slot {
        /// The global slot number of a chain or block
        uint256 slot_number;
        /// Number of slots per epoch
        uint256 slots_per_epoch;
    }

    struct epoch_ledger {
        /// A unique identifier of the EpochLedger
        uint256 hash;
        /// The total currency in circulation after the block was produced. New issuance is via the coinbase reward and new account fees can reduce the total issuance.
        uint256 total_currency;
    }

    struct epoch_data {
        /// Epoch Ledger, contains ledger related data for the epoch
        epoch_ledger ledger;
        ///  Initialize the random number generator
        uint256 epoch_seed;
        /// State hash of first block of epoch
        uint256 start_checkpoint;
        /// State hash of last known block in the first 2/3 of epoch (excluding the current state)
        uint256 lock_checkpoint;
        /// Length of an epoch
        uint256 epoch_length;
    }
}