// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//
pragma solidity >=0.8.4;

import "../types.sol";
import "./fri_verifier_calldata.sol";
import "../algebra/polynomial.sol";
import "../basic_marshalling_calldata.sol";

library lpc_verifier_calldata {
    struct local_vars_type {
        uint256 z_len;
        uint256[] z;
    }

    uint256 constant m = 2;
    uint256 constant PROOF_Z_OFFSET = 0x28;

    function skip_proof_be(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 result_offset)
    {
        // T_root
        result_offset = basic_marshalling_calldata.skip_octet_vector_32_be(
            blob,
            offset
        );
        // z
        result_offset = basic_marshalling_calldata.skip_vector_of_uint256_be(
            blob,
            result_offset
        );
        // fri_proof
        uint256 value_len;
        (value_len, result_offset) = basic_marshalling_calldata.get_skip_length(
            blob,
            result_offset
        );
        for (uint256 i = 0; i < value_len; i++) {
            result_offset = fri_verifier_calldata.skip_proof_be(
                blob,
                result_offset
            );
        }
    }

    function skip_vector_of_proofs_be(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 result_offset)
    {
        uint256 value_len;
        (value_len, result_offset) = basic_marshalling_calldata.get_skip_length(
            blob,
            offset
        );
        for (uint256 i = 0; i < value_len; i++) {
            result_offset = skip_proof_be(blob, result_offset);
        }
    }

    function skip_n_proofs_in_vector_be(
        bytes calldata blob,
        uint256 offset,
        uint256 n
    ) internal pure returns (uint256 result_offset) {
        uint256 value_len;
        (value_len, result_offset) = basic_marshalling_calldata.get_skip_length(
            blob,
            offset
        );
        for (uint256 i = 0; i < n; i++) {
            result_offset = skip_proof_be(blob, result_offset);
        }
    }

    function get_z_i_from_proof_be(
        bytes calldata blob,
        uint256 offset,
        uint256 i
    ) internal pure returns (uint256 z_i) {
        // 0x28 (skip T_root)
        z_i = basic_marshalling_calldata.get_i_uint256_from_vector(
            blob,
            offset + 0x28,
            i
        );
    }

    function get_z_i_ptr_from_proof_be(
        bytes calldata blob,
        uint256 offset,
        uint256 i
    ) internal pure returns (uint256 z_i) {
        // 0x28 (skip T_root)
        z_i = basic_marshalling_calldata.get_i_uint256_ptr_from_vector(
            blob,
            offset + 0x28,
            i
        );
    }

    function get_z_0_ptr_from_proof_be(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 z_0_ptr)
    {
        // 0x28 (skip T_root) + 8 (lenght)
        assembly {
            z_0_ptr := add(blob.offset, add(offset, 0x30))
        }
    }

    function skip_proof_be_check(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 result_offset)
    {
        // T_root
        result_offset = basic_marshalling_calldata
            .skip_octet_vector_32_be_check(blob, offset);
        // z
        result_offset = basic_marshalling_calldata
            .skip_vector_of_uint256_be_check(blob, result_offset);
        // fri_proof
        uint256 value_len;
        (value_len, result_offset) = basic_marshalling_calldata
            .get_skip_length_check(blob, result_offset);
        for (uint256 i = 0; i < value_len; i++) {
            result_offset = fri_verifier_calldata.skip_proof_be_check(
                blob,
                result_offset
            );
        }
    }

    function skip_vector_of_proofs_be_check(bytes calldata blob, uint256 offset)
        internal
        pure
        returns (uint256 result_offset)
    {
        uint256 value_len;
        (value_len, result_offset) = basic_marshalling_calldata
            .get_skip_length_check(blob, offset);
        for (uint256 i = 0; i < value_len; i++) {
            result_offset = skip_proof_be_check(blob, result_offset);
        }
    }

    function skip_n_proofs_in_vector_be_check(
        bytes calldata blob,
        uint256 offset,
        uint256 n
    ) internal pure returns (uint256 result_offset) {
        uint256 value_len;
        (value_len, result_offset) = basic_marshalling_calldata
            .get_skip_length_check(blob, offset);
        require(n <= value_len);
        for (uint256 i = 0; i < n; i++) {
            result_offset = skip_proof_be_check(blob, result_offset);
        }
    }

    function get_z_i_from_proof_be_check(
        bytes calldata blob,
        uint256 offset,
        uint256 i
    ) internal pure returns (uint256 z_i) {
        // 0x28 (skip T_root)
        z_i = basic_marshalling_calldata.get_i_uint256_from_vector_check(
            blob,
            offset + 0x28,
            i
        );
    }

    function get_z_i_ptr_from_proof_be_check(
        bytes calldata blob,
        uint256 offset,
        uint256 i
    ) internal pure returns (uint256 z_i) {
        // 0x28 (skip T_root)
        z_i = basic_marshalling_calldata.get_i_uint256_ptr_from_vector_check(
            blob,
            offset + 0x28,
            i
        );
    }

    function get_z_0_ptr_from_proof_be_check(
        bytes calldata blob,
        uint256 offset
    ) internal pure returns (uint256 z_0_ptr) {
        // 0x28 (skip T_root) + 8 (lenght)
        assembly {
            z_0_ptr := add(blob.offset, add(offset, 0x30))
        }
    }

    function parse_verify_proof_be(
        bytes calldata blob,
        uint256 offset,
        uint256[] memory evaluation_points,
        types.transcript_data memory tr_state,
        types.lpc_params_type memory params
    ) internal view returns (bool result, uint256 proof_size) {
        result = false;
        require(offset < blob.length);
        uint256 len = blob.length - offset;
        proof_size = PROOF_Z_OFFSET + 8;
        require(proof_size <= len);
        local_vars_type memory local_vars;
        assembly {
            let z_len := shr(
                0xc0,
                calldataload(add(blob.offset, add(offset, PROOF_Z_OFFSET)))
            )
            proof_size := add(proof_size, mul(0x20, z_len))
            mstore(local_vars, z_len)
        }

        require(proof_size + 8 <= len);
        assembly {
            let fri_proof_len := shr(
                0xc0,
                calldataload(add(blob.offset, add(offset, proof_size)))
            )
            // number of fri proofs should be equal to lambda
            if iszero(
                eq(
                    fri_proof_len,
                    // lambda
                    mload(add(params, 0x20))
                )
            ) {
                revert(0, 0)
            }
            proof_size := add(proof_size, 8)
        }

        local_vars.z = new uint256[](local_vars.z_len);
        assembly {
            let z_ptr := add(mload(add(local_vars, 0x20)), 0x20)
            let local_off := add(add(offset, PROOF_Z_OFFSET), 8)
            for {
                let i := 0
            } lt(i, mul(0x20, mload(local_vars))) {
                i := add(i, 0x20)
            } {
                mstore(add(z_ptr, i), calldataload(add(blob.offset, local_off)))
                local_off := add(local_off, 0x20)
            }
        }
        params.fri_params.U = polynomial.interpolate(
            evaluation_points,
            local_vars.z,
            params.modulus
        );
        params.fri_params.V = new uint256[](1);
        params.fri_params.V[0] = 1;
        uint256[] memory a_poly = new uint256[](2);
        a_poly[1] = 1;
        for (uint256 j = 0; j < evaluation_points.length; j++) {
            a_poly[0] = params.modulus - evaluation_points[j];
            params.fri_params.V = polynomial.mul_poly(
                params.fri_params.V,
                a_poly,
                params.modulus
            );
        }
        for (uint256 round_id = 0; round_id < params.lambda; round_id++) {
            (bool result_i, uint256 read_fri_proof_size) = fri_verifier_calldata
                .parse_verify_proof_be(
                    blob,
                    offset + proof_size,
                    tr_state,
                    params.fri_params
                );
            if (!result_i) {
                return (false, 0);
            }
            proof_size += read_fri_proof_size;
        }
        result = true;
    }
}
