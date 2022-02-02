// SPDX-License-Identifier: Apache-2.0.
pragma solidity >=0.6.11;

import "./memory_map.sol";

contract memory_access_utils is memory_map {
    function ptr(uint256[] memory ctx, uint256 offset) internal pure returns (uint256) {
        uint256 ctxPtr;
        require(offset < MM_CONTEXT_SIZE, "Overflow protection failed");
        assembly {
            ctxPtr := add(ctx, 0x20)
        }
        return ctxPtr + offset * 0x20;
    }

    function proof_ptr(uint256[] memory proof) internal pure returns (uint256) {
        uint256 proofPtr;
        assembly {
            proofPtr := proof
        }
        return proofPtr;
    }

    function channel_ptr(uint256[] memory ctx) internal pure returns (uint256) {
        uint256 ctxPtr;
        assembly {
            ctxPtr := add(ctx, 0x20)
        }
        return ctxPtr + MM_CHANNEL * 0x20;
    }

    function merkle_queue_ptr(uint256[] memory ctx) internal pure returns (uint256) {
        return ptr(ctx, MM_MERKLE_QUEUE);
    }

    function getFriSteps(uint256[] memory ctx) internal pure returns (uint256[] memory friSteps) {
        uint256 friStepsPtr = ptr(ctx, MM_FRI_STEPS_PTR);
        assembly {
            friSteps := mload(friStepsPtr)
        }
    }
}
