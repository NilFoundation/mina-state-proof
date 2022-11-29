// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

import "./constants.sol";
import {consensus} from "./state.sol";

library selection {
    /// Top level API to select between chains during a fork.
    function select_secure_chain(selection[] candidates) {
        for (uint256 itr = 0; itr < candidates.length; itr++) {
            if (is_short_range(candidate)) {
                // short-range fork, select longer chain
                select_longer_chain(candidate);
            } else {
                // check against sub window density sizes > 11
                state.consensus candidate_state = candidate.consensus_state();

                // sub window density must not be greater than initial genesis subwindow density value.
                for (uint256 itr = 0; itr < candidate_state.sub_window_densities().length; itr++) {
                    if (candidate_state.sub_window_densities[itr] > config().slots_per_sub_window) {continue;
                    }
                }

                // sub window densities must not be greater than sub_windows_per_window
                uint256 sub_windows_per_window = config().sub_windows_per_window;
                if (candidate_state.sub_window_densities.length != sub_windows_per_window) {
                    continue;
                }

                uint32 tip_density = relative_min_window_density(candidate);
                uint32 candidate_density = candidate.relative_min_window_density(this);

                if (candidate_density > tip_density) {
                    self = candidate;
                }
            }
        }
    }

    /// Selects the longer chain when there's a short range fork.
    function select_longer_chain(selection candidate) {
        state.consensus top_state = consensus_state();
        state.consensus candidate_state = candidate.consensus_state();

        if (top_state.blockchain_length < candidate_state.blockchain_length) {
            self = candidate;
        } else if (top_state.blockchain_length == candidate_state.blockchain_length) {
            // tiebreak logic
            if (candidate.last_vrf_hash_digest() == last_vrf_hash_digest()) {
                if (candidate.state_hash() > state_hash()) {
                    self = candidate;
                }
            } else if (candidate.last_vrf_hash_digest() > last_vrf_hash_digest()) {
                self = candidate;
            }
        }
    }
}

/// Checks whether the fork is short range wrt to candidate chain
    function is_short_range(selection candidate) returns (bool);

/// Calculates the relate minimum window density wrt to candidate chain.
    function relative_min_window_density(selection candidate) returns (uint32);

/// Constants used for consensus
    function config() returns (consensus_constants constants);
}