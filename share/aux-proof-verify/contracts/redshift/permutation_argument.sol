// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

import '../types.sol';

library permutation_argument {
    uint256 constant ARGUMENT_SIZE = 3;

    function verify_eval_be(
        types.permutation_argument_eval_params memory params
    ) internal pure returns (uint256[] memory F) {
        require(params.id_permutation_ptrs.length >= params.column_polynomials_values.length, "");
        require(params.sigma_permutation_ptrs.length >= params.column_polynomials_values.length, "");

        F = new uint256[](ARGUMENT_SIZE);
        
        assembly {
            let modulus := mload(params)
            let g := 1
            let h := 1

            for { let offset := 0x20 }
            lt(offset, add(0x20, mul(0x20, mload(mload(add(params, 0x40))))))
            { offset := add(offset, 0x20) } {
                g := mulmod(
                    g,
                    // column_polynomials_values[i] + beta * S_id[i].evaluate(challenge) + gamma
                    addmod(
                        // column_polynomials_values[i]
                        mload(add(mload(add(params, 0x40)), offset)),
                        // beta * S_id[i].evaluate(challenge) + gamma
                        addmod(
                            // beta * S_id[i].evaluate(challenge)
                            mulmod(
                                // beta
                                mload(add(params, 0xe0)),
                                // S_id[i].evaluate(challenge)
                                mload(mload(add(mload(add(params, 0x60)), offset))),
                                modulus
                            ),
                            // gamma
                            mload(add(params, 0x100)),
                            modulus
                        ),
                        modulus
                    ),
                    modulus
                )
                h := mulmod(
                    h,
                    // column_polynomials_values[i] + beta * S_sigma[i].evaluate(challenge) + gamma
                    addmod(
                        // column_polynomials_values[i]
                        mload(add(mload(add(params, 0x40)), offset)),
                        // beta * S_sigma[i].evaluate(challenge) + gamma
                        addmod(
                            // beta * S_sigma[i].evaluate(challenge)
                            mulmod(
                                // beta
                                mload(add(params, 0xe0)),
                                // S_sigma[i].evaluate(challenge)
                                mload(mload(add(mload(add(params, 0x80)), offset))),
                                modulus
                            ),
                            // gamma
                            mload(add(params, 0x100)),
                            modulus
                        ),
                        modulus
                    ),
                    modulus
                )
            }

            // F[0]
            // challenge
            switch mload(add(params, 0x20))
            case 1 {
                // TODO: check case
                mstore(
                    add(F, 0x20),
                    // preprocessed_data.common_data.lagrange_0.evaluate(challenge) *
                    //  (one - perm_polynomial_value)
                    addmod(
                        1,
                        // one - perm_polynomial_value
                        sub(modulus, mload(add(params, 0xa0))),
                        modulus
                    )
                )
            }
            default {
                mstore(add(F, 0x20), 0)
            }

            // F[1]
            mstore(
                add(F, 0x40),
                // (one - preprocessed_data.q_last.evaluate(challenge) -
                //  preprocessed_data.q_blind.evaluate(challenge)) *
                //  (perm_polynomial_shifted_value * h - perm_polynomial_value * g)
                mulmod(
                    // one - preprocessed_data.q_last.evaluate(challenge) -
                    //  preprocessed_data.q_blind.evaluate(challenge)
                    addmod(
                        1,
                        // - preprocessed_data.q_last.evaluate(challenge) - preprocessed_data.q_blind.evaluate(challenge)
                        addmod(
                            // -preprocessed_data.q_last.evaluate(challenge)
                            sub(modulus, mload(add(params, 0x140))),
                            // -preprocessed_data.q_blind.evaluate(challenge)
                            sub(modulus, mload(add(params, 0x120))),
                            modulus
                        ),
                        modulus
                    ),
                    // perm_polynomial_shifted_value * h - perm_polynomial_value * g
                    addmod(
                        // perm_polynomial_shifted_value * h
                        mulmod(
                            // perm_polynomial_shifted_value
                            mload(add(params, 0xc0)),
                            h,
                            modulus
                        ),
                        // - perm_polynomial_value * g
                        sub(
                            modulus, 
                            mulmod(
                                // perm_polynomial_value
                                mload(add(params, 0xa0)),
                                g,
                                modulus
                            )
                        ),
                        modulus
                    ),
                    modulus
                )
            )

            // F[2]
            // preprocessed_data.q_last.evaluate(challenge) *
            //  (perm_polynomial_value.squared() - perm_polynomial_value)
            mstore(
                add(F, 0x60),
                mulmod(
                    // preprocessed_data.q_last.evaluate(challenge)
                    mload(add(params, 0x140)),
                    // perm_polynomial_value.squared() - perm_polynomial_value
                    addmod(
                        // perm_polynomial_value.squared()
                        mulmod(
                            // perm_polynomial_value
                            mload(add(params, 0xa0)),
                            // perm_polynomial_value
                            mload(add(params, 0xa0)),
                            modulus
                        ),
                        // -perm_polynomial_value
                        sub(modulus, mload(add(params, 0xa0))),
                        modulus
                    ),
                    modulus
                )
            )
        }
    }
}
