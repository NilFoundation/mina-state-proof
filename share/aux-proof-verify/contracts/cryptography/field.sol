// SPDX-License-Identifier: MIT OR Apache-2.0
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
pragma solidity >=0.6.0;
pragma experimental ABIEncoderV2;

/**
 * @title Bn254 elliptic curve crypto
 * @dev Provides some basic methods to compute bilinear pairings, construct group elements and misc numerical methods
 */
library field {
    // Perform a modular exponentiation. This method is ideal for small exponents (~64 bits or less), as
    // it is cheaper than using the pow precompile
    function pow_small(uint256 base, uint256 exponent, uint256 modulus) internal pure returns (uint256) {
        uint256 result = 1;
        uint256 input = base;
        uint256 count = 1;

        assembly {
            let endpoint := add(exponent, 0x01)
            for {} lt(count, endpoint) {count := add(count, count)}
            {
                if and(exponent, count) {
                    result := mulmod(result, input, modulus)
                }
                input := mulmod(input, input, modulus)
            }
        }

        return result;
    }

    /// @dev Modular inverse of a (mod p) using euclid.
    /// 'a' and 'p' must be co-prime.
    /// @param a The number.
    /// @param p The mmodulus.
    /// @return x such that ax = 1 (mod p)
    function invmod(uint256 a, uint256 p) internal pure returns (uint256) {
        require(a != 0 && a != p && p != 0);
        if (a > p)
            a = a % p;
        int256 t1;
        int256 t2 = 1;
        uint256 r1 = p;
        uint256 r2 = a;
        uint256 q;
        while (r2 != 0) {
            q = r1 / r2;
            (t1, t2, r1, r2) = (t2, t1 - int256(q) * t2, r2, r1 - q * r2);
        }
        if (t1 < 0)
            return (p - uint256(-t1));
        return uint256(t1);
    }

    function fadd(uint256 a, uint256 b, uint256 modulus) internal pure returns (uint256 result) {
        assembly {
            result := addmod(a, b, modulus)
        }
    }

    function fsub(uint256 a, uint256 b, uint256 modulus) internal pure returns (uint256 result) {
        assembly {
            result := addmod(a, sub(modulus, b), modulus)
        }
    }

    function fmul(uint256 a, uint256 b, uint256 modulus) internal pure returns (uint256 result) {
        assembly {
            result := mulmod(a, b, modulus)
        }
    }

    function fdiv(uint256 a, uint256 b, uint256 modulus) internal pure returns (uint256 result) {
        uint256 b_inv = invmod(b, modulus);
        assembly {
            result := mulmod(a, b_inv, modulus)
        }
    }
}