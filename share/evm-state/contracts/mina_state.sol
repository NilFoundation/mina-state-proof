pragma solidity ^0.8.0;

import "./state.sol";

contract mina_state {
    function verify(
        bytes calldata blob,
        uint256[] calldata init_params,
        int256[][] calldata columns_rotations
    ) external view returns (bool verified) {
    }
}