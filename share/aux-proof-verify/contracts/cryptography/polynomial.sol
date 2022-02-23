// SPDX-License-Identifier: MIT OR Apache-2.0
//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

import './field.sol';

/**
 * @title Turbo Plonk polynomial evaluation
 * @dev Implementation of Turbo Plonk's polynomial evaluation algorithms
 *
 * Expected to be inherited by `TurboPlonk.sol`
 */
library polynomial {
    /*
      Computes the evaluation of a polynomial f(x) = sum(a_i * x^i) on the given point.
      The coefficients of the polynomial are given in
        a_0 = coefsStart[0], ..., a_{n-1} = coefsStart[n - 1]
      where n = nCoeffs = friLastLayerDegBound. Note that coefsStart is not actually an array but
      a direct pointer.
      The function requires that n is divisible by 8.
    */
    function evaluate(
        uint256[] memory coeffs,
        uint256 point,
        uint256 modulus
    ) internal pure returns (uint256) {
        uint256 result = 0;
        uint256 x_pow = 1;
        for (uint256 i = 0; i < coeffs.length; i++) {
            assembly {
                result := addmod(result, mulmod(x_pow, mload(add(add(coeffs, 0x20), mul(i, 0x20))), modulus), modulus)
                x_pow := mulmod(x_pow, point, modulus)
            }
        }
        return result;
    }

    function add_poly(
        uint256[] memory a,
        uint256[] memory b,
        uint256 modulus
    ) internal pure returns (uint256[] memory) {
        uint256 len;
        if (a.length < b.length) {
            len = b.length;
        } else {
            len = a.length;
        }

        uint256[] memory results = new uint256[](len);

        for (uint256 i = 0; i < len; i++) {
            uint256 aOrZero = a.length > i ? a[i] : 0;
            uint256 bOrZero = b.length > i ? b[i] : 0;
            assembly {
                mstore(add(add(results, 0x20), mul(i, 0x20)), addmod(aOrZero, bOrZero, modulus))
            }
        }

        return results;
    }

    function mul_poly(
        uint256[] memory a,
        uint256[] memory b,
        uint256 modulus
    ) internal pure returns (uint256[] memory resultTerms) {
        uint256 padding = 0;
        for (uint256 i = 0; i < b.length; i++) {
            uint256[] memory currentValues = new uint256[](a.length + padding);
            uint256 aTerm;
            uint256 bTerm;
            // TODO: seems redundant
            for (uint256 k = 0; k < padding; k++) {
//                currentValues[k] = 0;
                assembly {
                    mstore(add(add(currentValues, 0x20), mul(k, 0x20)), 0)
                }
            }
            for (uint256 j = 0; j < a.length; j++) {
//                uint256 aTerm = a[j];
//                uint256 bTerm = b[i];
//                currentValues[j + padding] = aTerm.gf256Mul(bTerm);
                assembly {
                    aTerm := mload(add(add(a, 0x20), mul(j, 0x20)))
                    bTerm := mload(add(add(b, 0x20), mul(i, 0x20)))
                    mstore(add(add(currentValues, 0x20), mul(add(j, padding), 0x20)), mulmod(aTerm, bTerm, modulus))
                }
            }
            resultTerms = add_poly(resultTerms, currentValues, modulus);
            padding += 1;
        }
    }

    function lagrange_interpolation(
        uint256[] memory xs,
        uint256[] memory fxs,
        uint256 modulus
    ) internal pure returns (uint256[] memory result) {
        require(xs.length == fxs.length);
        uint256 len = fxs.length;
        for (uint256 i = 0; i < len; i++) {
            uint256[] memory thisPoly = new uint256[](1);
            thisPoly[0] = 1;
            for (uint256 j = 0; j < len; j++) {
                if (i == j) {
                    continue;
                }
                uint256 denominator = field.fsub(xs[i], xs[j], modulus);
                uint256[] memory thisTerm = new uint256[](2);
                thisTerm[0] = field.fdiv(modulus - xs[j], denominator, modulus);
                thisTerm[1] = field.fdiv(uint256(1), denominator, modulus);
                thisPoly = mul_poly(thisPoly, thisTerm, modulus);
            }
            if (fxs.length + 1 >= i) {
                uint256[] memory multiple = new uint256[](1);
                multiple[0] = fxs[i];
                thisPoly = mul_poly(thisPoly, multiple, modulus);
            }
            result = add_poly(result, thisPoly, modulus);
        }
    }
}
