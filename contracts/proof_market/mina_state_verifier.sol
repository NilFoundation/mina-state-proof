// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import '@nilfoundation/evm-placeholder-verification/contracts/interfaces/verifier.sol';


contract MinaStateVerifier is Ownable {
    address _verifier;

    address _base_gates;
    address _scalar_gates;
    uint256[][] _init_params;
    int256[][][] _columns_rotations;

    IVerifier v;

    constructor(
        address verifier,
        address base_gates,
        address scalar_gates,
        uint256[][] memory init_params,
        int256[][][] memory columns_rotations
    ) {
        _verifier = verifier;
        _base_gates = base_gates;
        _scalar_gates = scalar_gates;
        _init_params = init_params;
        _columns_rotations = columns_rotations;

        v = IVerifier(_verifier);
    }

    function setVerifier(address verifier) external onlyOwner {
        _verifier = verifier;
        v = IVerifier(_verifier);
    }

    function setBaseGates(address base_gates) external onlyOwner {
        _base_gates = base_gates;
    }

    function setScalarGates(address scalar_gates) external onlyOwner {
        _scalar_gates = scalar_gates;
    }

    function verify(
        bytes calldata blob,
        // TODO: add public_inputs
        uint256[] calldata public_input
    ) external view returns (bool) {
        uint256 size1 = _init_params[0][0];
        uint256 size2 = _init_params[0][1];

        return size1 + size2 == blob.length &&
        v.verify(blob[0 : size1],
            _init_params[1], _columns_rotations[0], _base_gates) &&
        v.verify(blob[size1 : blob.length],
            _init_params[2], _columns_rotations[1], _scalar_gates);
    }
}
