// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

//import "./constants.sol";
//import "./state.sol";

library selection {
//    /// Top level API to select between chains during a fork.
//    function select_secure_chain(selection[] candidates) {
//        for (uint256 itr = 0; itr < candidates.length; itr++) {
//            if (is_short_range(candidate)) {
//                // short-range fork, select longer chain
//                select_longer_chain(candidate);
//            } else {
//                // check against sub window density sizes > 11
//                state.consensus candidate_state = candidate.consensus_state();
//
//                // sub window density must not be greater than initial genesis subwindow density value.
//                for (uint256 itr = 0; itr < candidate_state.sub_window_densities.length; itr++) {
//                    if (candidate_state.sub_window_densities[itr] > config().slots_per_sub_window) {continue;
//                    }
//                }
//
//                // sub window densities must not be greater than sub_windows_per_window
//                uint256 sub_windows_per_window = config().sub_windows_per_window;
//                if (candidate_state.sub_window_densities.length != sub_windows_per_window) {
//                    continue;
//                }
//
//                uint32 tip_density = relative_min_window_density(candidate);
//                uint32 candidate_density = candidate.relative_min_window_density(this);
//
//                if (candidate_density > tip_density) {
//                    self = candidate;
//                }
//            }
//        }
//    }
//
//    /// Selects the longer chain when there's a short range fork.
//    function select_longer_chain(selection candidate) {
//        state.consensus top_state = consensus_state();
//        state.consensus candidate_state = candidate.consensus_state();
//
//        if (top_state.blockchain_length < candidate_state.blockchain_length) {
//            self = candidate;
//        } else if (top_state.blockchain_length == candidate_state.blockchain_length) {
//            // tiebreak logic
//            if (candidate.last_vrf_hash_digest() == last_vrf_hash_digest()) {
//                if (candidate.state_hash() > state_hash()) {
//                    self = candidate;
//                }
//            } else if (candidate.last_vrf_hash_digest() > last_vrf_hash_digest()) {
//                self = candidate;
//            }
//        }
//    }
//
//    function check_consensus_state(state.consensus s1, state.consensus s2, uint32 s2_epoch_slot) returns (bool) {
//        if (s1.epoch_count == s2.epoch_count + 1 && s2_epoch_slot >= self.config().slots_per_epoch * 2 / 3) {
//            // S1 is one epoch ahead of S2 and S2 is not in the seed update range
//            return s1.staking_epoch_data.lock_checkpoint == s2.next_epoch_data.lock_checkpoint;
//        } else {
//            return false;
//        }
//    }
//
//    /// Checks whether the fork is short range wrt to candidate chain
//    function is_short_range(selection candidate) returns (bool) {
//        state.consensus a = consensus_state();
//        state.consensus b = candidate.consensus_state;
//        uint256 a_prev_lock_checkpoint = a.staking_epoch_data.lock_checkpoint;
//        uint256 b_prev_lock_checkpoint = b.staking_epoch_data.lock_checkpoint;
//
//        if (a.epoch_count == b.epoch_count) {
//            // Simple case: blocks have same previous epoch, so compare previous epochs' lock_checkpoints
//            return a_prev_lock_checkpoint == b_prev_lock_checkpoint;
//        } else {
//            // Check for previous epoch case using both orientations
//            return check_consensus_state(a, b, candidate.epoch_slot()) || check_consensus_state(b, a, self.epoch_slot());
//        }
//    }
//
//    function max(uint256 a, uint256 b) external pure returns (uint256) {
//        return a >= b ? a : b;
//    }
//
//    function min(uint256 a, uint256 b) external pure returns (uint256) {
//        return a <= b ? a : b;
//    }
//
//    function compute_projective_window(selection tip_state) returns (uint256[]) {
//        // compute shift count
//        uint256 shift_count = min(max(max_slot - tip_state.curr_global_slot.slot_number - 1, 0),
//            config().sub_windows_per_window);
//        // initialize projected window based off of chain_a
//        uint256[] projected_window = tip_state.sub_window_densities;
//
//        // relative sub window
//        uint256 rel_sub_window = tip_state.curr_global_slot.slot_number / config().sub_windows_per_window % config().sub_windows_per_window;
//
//        // ring shift
//        while (shift_count > 0) {
//            rel_sub_window = (rel_sub_window + 1) % config().sub_windows_per_window;
//            if (projected_window[rel_sub_window]) {
//                projected_window[rel_sub_window] = 0;
//            }
//            shift_count -= 1;
//        }
//
//        return projected_window;
//    }
//
//    /// Calculates the relate minimum window density wrt to candidate chain.
//    function relative_min_window_density(selection candidate) returns (uint32) {
//        state.consensus tip_state = consensus_state();
//        state.consensus chain_b = candidate.consensus_state();
//
//        uint256 max_slot = max(tip_state.curr_global_slot.slot_number, chain_b.curr_global_slot.slot_number);
//
//        // grace-period rule
//        if (max_slot < config().grace_period_end) {
//            return tip_state.min_window_density;
//        }
//
//        uint256[] projected_window = compute_projective_window(tip_state);
//
//        // compute projected window density
//        uint256 projected_window_density = 0;
//        for (uint256 itr = 0; itr < projected_window.length; itr++) {
//            projected_window_density + projected_window[itr];
//        }
//
//        // compute minimum window density
//        return min(tip_state.min_window_density, projected_window_density);
//    }
//
//    /// Constants used for consensus
//    function config() returns (consensus_constants constants);
}