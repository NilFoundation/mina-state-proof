// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import '@nilfoundation/evm-placeholder-verification/contracts/interfaces/verifier.sol';


contract AccountPathVerifier is Ownable {

    address _verifier;
    address _gates;
    uint256[] _init_params;
    int256[][] _columns_rotations;

    constructor(
        address verifier,
        address gates,
        uint256[] memory init_params,
        int256[][] memory columns_rotations        
    ) {
        _verifier = verifier;
        _gates = gates;
        _init_params = init_params;
        _columns_rotations = columns_rotations;
    }

    function setVerifier(address verifier) external onlyOwner {
        _verifier = verifier;
    }

    function setGates(address gates) external onlyOwner {
        _gates = gates;
    }

    function verify(
        bytes calldata blob,
        uint256[] calldata public_input
    ) external view returns (bool) {
        IVerifier v = IVerifier(_verifier);
        return v.verify(blob, _init_params, _columns_rotations, _gates);
    }
}