// SPDX-License-Identifier: Apache-2.0.
pragma solidity >=0.6.11;

import "./memory_map.sol";

contract memory_access_utils is memory_map {
    function getPtr(uint256[] memory ctx, uint256 offset) internal pure returns (uint256) {
        uint256 ctxPtr;
        require(offset < MM_CONTEXT_SIZE, "Overflow protection failed");
        assembly {
            ctxPtr := add(ctx, 0x20)
        }
        return ctxPtr + offset * 0x20;
    }

    function getProofPtr(uint256[] memory proof) internal pure returns (uint256) {
        uint256 proofPtr;
        assembly {
            proofPtr := proof
        }
        return proofPtr;
    }

    function getChannelPtr(uint256[] memory ctx) internal pure returns (uint256) {
        uint256 ctxPtr;
        assembly {
            ctxPtr := add(ctx, 0x20)
        }
        return ctxPtr + MM_CHANNEL * 0x20;
    }

    function getMerkleQueuePtr(uint256[] memory ctx) internal pure returns (uint256) {
        return getPtr(ctx, MM_MERKLE_QUEUE);
    }

    function getFriSteps(uint256[] memory ctx) internal pure returns (uint256[] memory friSteps) {
        uint256 friStepsPtr = getPtr(ctx, MM_FRI_STEPS_PTR);
        assembly {
            friSteps := mload(friStepsPtr)
        }
    }
}
