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

pragma solidity >=0.8.4;

import "./field.sol";

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
                result := addmod(
                    result,
                    mulmod(
                        x_pow,
                        mload(add(add(coeffs, 0x20), mul(i, 0x20))),
                        modulus
                    ),
                    modulus
                )
                x_pow := mulmod(x_pow, point, modulus)
            }
        }
        return result;
    }

    function evaluate_by_ptr(
        bytes memory blob,
        uint256 offset,
        uint256 len,
        uint256 point,
        uint256 modulus
    ) internal pure returns (uint256) {
        uint256 result = 0;
        uint256 x_pow = 1;
        for (uint256 i = 0; i < len; i++) {
            assembly {
                result := addmod(
                    result,
                    mulmod(
                        x_pow,
                        mload(add(add(add(blob, 0x20), offset), mul(i, 0x20))),
                        modulus
                    ),
                    modulus
                )
                x_pow := mulmod(x_pow, point, modulus)
            }
        }
        return result;
    }

    function evaluate_by_ptr_calldata(
        bytes calldata blob,
        uint256 offset,
        uint256 len,
        uint256 point,
        uint256 modulus
    ) internal pure returns (uint256) {
        uint256 result = 0;
        uint256 x_pow = 1;
        for (uint256 i = 0; i < len; i++) {
            assembly {
                result := addmod(
                    result,
                    mulmod(
                        x_pow,
                        calldataload(
                            add(add(blob.offset, offset), mul(i, 0x20))
                        ),
                        modulus
                    ),
                    modulus
                )
                x_pow := mulmod(x_pow, point, modulus)
            }
        }
        return result;
    }

    function add_poly(
        uint256[] memory a,
        uint256[] memory b,
        uint256 modulus
    ) internal pure returns (uint256[] memory result) {
        // [0] = minLen
        // [1] = maxLen
        // [3] = longArr
        uint256[] memory local_vars = new uint256[](3);
        if (a.length < b.length) {
            assembly {
                mstore(add(local_vars, 0x20), mload(a))
                mstore(add(local_vars, 0x40), mload(b))
                mstore(add(local_vars, 0x60), b)
            }
        } else {
            assembly {
                mstore(add(local_vars, 0x20), mload(b))
                mstore(add(local_vars, 0x40), mload(a))
                mstore(add(local_vars, 0x60), a)
            }
        }

        result = new uint256[](local_vars[1]);

        assembly {
            for {
                let i := 0
            } lt(i, mul(mload(add(local_vars, 0x20)), 0x20)) {
                i := add(i, 0x20)
            } {
                mstore(
                    add(add(result, 0x20), i),
                    addmod(
                        mload(add(add(a, 0x20), i)),
                        mload(add(add(b, 0x20), i)),
                        modulus
                    )
                )
            }
            for {
                let i := mul(mload(add(local_vars, 0x20)), 0x20)
            } lt(i, mul(mload(add(local_vars, 0x40)), 0x20)) {
                i := add(i, 0x20)
            } {
                mstore(
                    add(add(result, 0x20), i),
                    mload(add(mload(add(local_vars, 0x60)), add(0x20, i)))
                )
            }
        }
    }

    function mul_poly(
        uint256[] memory a,
        uint256[] memory b,
        uint256 modulus
    ) internal pure returns (uint256[] memory result) {
        if (b.length > a.length) {
            uint256[] memory tmp = a;
            a = b;
            b = tmp;
        }
        for (uint256 i = 0; i < b.length; i++) {
            uint256[] memory currentValues = new uint256[](a.length + i);
            for (uint256 j = 0; j < a.length; j++) {
                // currentValues[j + i] = a[j] * b[i];
                assembly {
                    mstore(
                        add(add(currentValues, 0x20), mul(add(j, i), 0x20)),
                        mulmod(
                            mload(add(add(a, 0x20), mul(j, 0x20))),
                            mload(add(add(b, 0x20), mul(i, 0x20))),
                            modulus
                        )
                    )
                }
            }
            result = add_poly(result, currentValues, modulus);
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

    function interpolate_evaluate_by_2_points_neg_x(
        uint256 x,
        uint256 dblXInv,
        uint256 fX,
        uint256 fMinusX,
        uint256 evalPoint,
        uint256 modulus
    ) internal pure returns (uint256 result) {
        assembly {
            result := addmod(
                mulmod(
                    mulmod(
                        addmod(fX, sub(modulus, fMinusX), modulus),
                        dblXInv,
                        modulus
                    ),
                    addmod(evalPoint, sub(modulus, x), modulus),
                    modulus
                ),
                fX,
                modulus
            )
        }
    }

    function interpolate_evaluate_by_2_points(
        uint256[] memory x,
        uint256[] memory fx,
        uint256 eval_point,
        uint256 modulus
    ) internal view returns (uint256 result) {
        require(x.length == 2, "x length is not equal to 2");
        require(fx.length == 2, "fx length is not equal to 2");
        uint256 x2_minus_x1_inv = field.inverse_static(
            (x[1] + (modulus - x[0])) % modulus,
            modulus
        );
        assembly {
            let y2_minus_y1 := addmod(
                mload(add(fx, 0x40)),
                sub(modulus, mload(add(fx, 0x20))),
                modulus
            )
            let x3_minus_x1 := addmod(
                eval_point,
                sub(modulus, mload(add(x, 0x20))),
                modulus
            )
            result := addmod(
                mulmod(
                    mulmod(y2_minus_y1, x2_minus_x1_inv, modulus),
                    x3_minus_x1,
                    modulus
                ),
                mload(add(fx, 0x20)),
                modulus
            )
        }
    }

    function interpolate_evaluate(
        uint256[] memory x,
        uint256[] memory fx,
        uint256 eval_point,
        uint256 modulus
    ) internal view returns (uint256) {
        if (x.length == 1 && fx.length == 1) {
            return fx[0];
        }
        if (x.length == 2) {
            return interpolate_evaluate_by_2_points(x, fx, eval_point, modulus);
        }
        require(false, "unsupported number of points for interpolation");
        return 0;
    }

    function interpolate_by_2_points(
        uint256[] memory x,
        uint256[] memory fx,
        uint256 modulus
    ) internal view returns (uint256[] memory result) {
        require(x.length == 2, "x length is not equal to 2");
        require(fx.length == 2, "fx length is not equal to 2");
        uint256 x2_minus_x1_inv = field.inverse_static(
            (x[1] + (modulus - x[0])) % modulus,
            modulus
        );
        result = new uint256[](2);
        assembly {
            let y2_minus_y1 := addmod(
                mload(add(fx, 0x40)),
                sub(modulus, mload(add(fx, 0x20))),
                modulus
            )
            let a := mulmod(y2_minus_y1, x2_minus_x1_inv, modulus)
            let a_mul_x1_neg := sub(
                modulus,
                mulmod(a, mload(add(x, 0x20)), modulus)
            )
            let b := addmod(mload(add(fx, 0x20)), a_mul_x1_neg, modulus)
            mstore(add(result, 0x20), b)
            mstore(add(result, 0x40), a)
        }
    }

    function interpolate(
        uint256[] memory x,
        uint256[] memory fx,
        uint256 modulus
    ) internal view returns (uint256[] memory) {
        if (x.length == 1 && fx.length == 1) {
            uint256[] memory result = new uint256[](1);
            result[0] = fx[0];
            return result;
        }
        if (x.length == 2) {
            return interpolate_by_2_points(x, fx, modulus);
        }
        require(false, "unsupported number of points for interpolation");
    }
}
