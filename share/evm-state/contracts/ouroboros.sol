// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

contract ouroboros {
    /// Constants used for the conensus
    /// Point of finality (number of confirmations)
    uint256 constant K = 290;
    /// Number of slots per epoch
    uint256 constant SLOTS_PER_EPOCH = 7140;
    /// No of slots in a sub-window = 7
    uint256 constant SLOTS_PER_SUB_WINDOW = 7;
    /// Maximum permissable delay of packets (in slots after the current)
    uint256 constant DELTA = 0;
    /// Timestamp of genesis block in unixtime
    uint256 constant GENESIS_STATE_TIMESTAMP = 1615939200000;
    /// Sub windows within a window
    uint256 constant SUB_WINDOWS_PER_WINDOW = 11;
    /// Number of slots before minimum density is used in chain selection
    uint256 constant GRACE_PERIOD_END = 1440;

    constructor() public {
    }
}
