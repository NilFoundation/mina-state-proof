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

pragma solidity >=0.8.4;

/**
 * @title Bn254Crypto library used for the fr, g1 and g2 point types
 * @dev Used to manipulate fr, g1, g2 types, perform modular arithmetic on them and call
 * the precompiles add, scalar mul and pairing
 *
 * Notes on optimisations
 * 1) Perform addmod, mulmod etc. in assembly - removes the check that Solidity performs to confirm that
 * the supplied modulus is not 0. This is safe as the modulus's used (r_mod, q_mod) are hard coded
 * inside the contract and not supplied by the user
 */
library types {
    uint256 constant PROGRAM_WIDTH = 4;
    uint256 constant NUM_NU_CHALLENGES = 11;

    uint256 constant coset_generator0 = 0x0000000000000000000000000000000000000000000000000000000000000005;
    uint256 constant coset_generator1 = 0x0000000000000000000000000000000000000000000000000000000000000006;
    uint256 constant coset_generator2 = 0x0000000000000000000000000000000000000000000000000000000000000007;

    // TODO: add external_coset_generator() method to compute this
    uint256 constant coset_generator7 = 0x000000000000000000000000000000000000000000000000000000000000000c;

    struct g1_point {
        uint256 x;
        uint256 y;
    }

    // G2 group element where x \in Fq2 = x0 * z + x1
    struct g2_point {
        uint256 x0;
        uint256 x1;
        uint256 y0;
        uint256 y1;
    }

    // N>B. Do not re-order these fields! They must appear in the same order as they
    // appear in the proof data
    struct proof {
        g1_point W1;
        g1_point W2;
        g1_point W3;
        g1_point W4;
        g1_point Z;
        g1_point T1;
        g1_point T2;
        g1_point T3;
        g1_point T4;
        uint256 w1;
        uint256 w2;
        uint256 w3;
        uint256 w4;
        uint256 sigma1;
        uint256 sigma2;
        uint256 sigma3;
        uint256 q_arith;
        uint256 q_ecc;
        uint256 q_c;
        uint256 linearization_polynomial;
        uint256 grand_product_at_z_omega;
        uint256 w1_omega;
        uint256 w2_omega;
        uint256 w3_omega;
        uint256 w4_omega;
        g1_point PI_Z;
        g1_point PI_Z_OMEGA;
        g1_point recursive_P1;
        g1_point recursive_P2;
        uint256 quotient_polynomial_eval;
    }

    struct challenge_transcript {
        uint256 alpha_base;
        uint256 alpha;
        uint256 zeta;
        uint256 beta;
        uint256 gamma;
        uint256 u;
        uint256 v0;
        uint256 v1;
        uint256 v2;
        uint256 v3;
        uint256 v4;
        uint256 v5;
        uint256 v6;
        uint256 v7;
        uint256 v8;
        uint256 v9;
        uint256 v10;
    }

    struct verification_key {
        uint256 circuit_size;
        uint256 num_inputs;
        uint256 work_root;
        uint256 domain_inverse;
        uint256 work_root_inverse;
        g1_point Q1;
        g1_point Q2;
        g1_point Q3;
        g1_point Q4;
        g1_point Q5;
        g1_point QM;
        g1_point QC;
        g1_point QARITH;
        g1_point QECC;
        g1_point QRANGE;
        g1_point QLOGIC;
        g1_point SIGMA1;
        g1_point SIGMA2;
        g1_point SIGMA3;
        g1_point SIGMA4;
        bool contains_recursive_proof;
        uint256 recursive_proof_indices;
        g2_point g2_x;

        // zeta challenge raised to the power of the circuit size.
        // Not actually part of the verification key, but we put it here to prevent stack depth errors
        uint256 zeta_pow_n;
    }
    
    struct transcript_data {
        bytes32 current_challenge;
    }

    struct path_element {
        uint256 position;
        bytes32 hash;
    }

    struct merkle_proof {
        uint256 li;
        bytes32 root;
        path_element[] path;
    }

    struct fri_params_type {
        uint256 modulus;
        uint256 r;
        uint256 max_degree;

        uint256[] D_omegas;
        uint256[] q;

        uint256[] U;
        uint256[] V;
    }

    struct fri_round_proof_type {
        uint256 colinear_value;
        bytes32 T_root;
        uint256[] y;
        merkle_proof colinear_path;
        merkle_proof[] p;
    }

    struct fri_proof_type {
        uint256[] final_polynomial;
        fri_round_proof_type[] round_proofs;
    }

    struct lpc_params_type {
        uint256 modulus;
        // 0x20
        uint256 lambda;
        // 0x40
        uint256 r;
        // 0x60
        uint256 m;
        // 0x80
        fri_params_type fri_params;
    }

    struct lpc_proof_type {
        bytes32 T_root;
        uint256[] z;
        fri_proof_type[] fri_proof;
    }

    struct gate_eval_params {
        uint256 modulus;
        // 0x20
        uint256 theta_acc;
        // 0x40
        uint256 theta;
        // 0x60
        uint256[] selector_evaluations_ptrs;
        // 0x80
        uint256 constraint_eval;
        // 0xa0
        uint256 gate_evaluation;
        // 0xc0
        bytes mds;
        // 0xe0
        bytes round_constants;
    }
    
    struct permutation_argument_eval_params {
        uint256 modulus;
        // 0x20
        uint256 challenge;
        // 0x40
        uint256[] column_polynomials_values;
        // 0x60
        uint256[] id_permutation_ptrs;
        // 0x80
        uint256[] sigma_permutation_ptrs;
        // 0xa0
        uint256 perm_polynomial_value;
        // 0xc0
        uint256 perm_polynomial_shifted_value;
        // 0xe0
        uint256 beta;
        // 0x100
        uint256 gamma;
        // 0x120
        uint256 q_blind_eval;
        // 0x140
        uint256 q_last_eval;
    }

    struct redshift_proof_map {
        uint256 witness_commitments_offset;
        uint256 T_commitments_offset;
        uint256 eval_proof_offset;
        uint256 eval_proof_witness_offset;
        uint256 eval_proof_permutation_offset;
        uint256 eval_proof_quotient_offset;
        uint256 eval_proof_id_permutation_offset;
        uint256 eval_proof_sigma_permutation_offset;
        uint256 eval_proof_public_input_offset;
        uint256 eval_proof_constant_offset;
        uint256 eval_proof_selector_offset;
        uint256 eval_proof_special_selectors_offset;
    }

    struct redshift_proof_map_calldata {
        uint256 v_perm_commitment_offset;
        // 0x20
        uint256 witness_commitments_offset;
        // 0x40
        uint256 T_commitments_offset;
        // 0x60
        uint256 eval_proof_offset;
        // 0x80
        uint256 eval_proof_witness_offset;
        // 0xa0
        uint256 eval_proof_permutation_offset;
        // 0xc0
        uint256 eval_proof_quotient_offset;
        // 0xe0
        uint256 eval_proof_id_permutation_offset;
        // 0x100
        uint256 eval_proof_sigma_permutation_offset;
        // 0x120
        uint256 eval_proof_public_input_offset;
        // 0x140
        uint256 eval_proof_constant_offset;
        // 0x160
        uint256 eval_proof_selector_offset;
        // 0x180
        uint256 eval_proof_special_selectors_offset;
    }

    struct redshift_column_rotations {
        int256[] rotations;
    }

    struct redshift_common_data {
        uint256 rows_amount;
        // 0x20
        uint256 omega;
        int256[][] columns_rotations; 
    }

    struct redshift_local_variables {
        uint256 len;
        // 0x20
        uint256 offset;
        // 0x40
        uint256 zero_index;
        // 0x60
        uint256[] permutation_argument;
        // 0x80
        uint256 gate_argument;
        // 0xa0
        uint256[] alphas;
        // 0xc0
        uint256 challenge;
        // 0xe0
        uint256 e;
        // 0x100
        uint256[] evaluation_points;
        // 0x120
        uint256[] F;
        // 0x140
        uint256 F_consolidated;
        // 0x160
        uint256 T_consolidated;
        // 0x180
        uint256 Z_at_challenge;
        // 0x1a0
        uint256 tmp1;
        bool status;
    }

    struct redshift_local_variables_calldata {
        uint256 len;
        // 0x20
        uint256 offset;
        // 0x40
        uint256 zero_index;
        // 0x60
        uint256[] permutation_argument;
        // 0x80
        uint256 gate_argument;
        // 0xa0
        uint256[] alphas;
        // 0xc0
        uint256 challenge;
        // 0xe0
        uint256 e;
        // 0x100
        uint256[] evaluation_points;
        // 0x120
        uint256[] F;
        // 0x140
        uint256 F_consolidated;
        // 0x160
        uint256 T_consolidated;
        // 0x180
        uint256 Z_at_challenge;
        // 0x1a0
        uint256 beta;
        // 0x1c0
        uint256 gamma;
        // 0x1e0
        uint256 g;
        // 0x200
        uint256 h;
        // 0x220
        uint256 perm_polynomial_value;
        // 0x240
        uint256 perm_polynomial_shifted_value;
        // 0x260
        uint256 q_blind_eval;
        // 0x280
        uint256 q_last_eval;
        // 0x2a0
        uint256 S_id_i;
        // 0x2c0
        uint256 S_sigma_i;
        uint256 tmp1;
        uint256 tmp2;
        uint256 tmp3;
        uint256 idx1;
        uint256 idx2;
        bool status;
    }

    struct gate_argument_local_vars {
        uint256 modulus;
        // 0x20
        uint256 theta;
        // 0x40
        uint256 constraint_eval;
        // 0x60
        uint256 gate_eval;
        // 0x80
        uint256[][] witness_evaluations;
        // 0xa0
        uint256[] selector_evaluations;
        // 0xc0
        uint256 eval_proof_witness_offset;
        // 0xe0
        uint256 eval_proof_selector_offset;
        // 0x100
        uint256 gates_evaluation;
        // 0x120
        uint256 theta_acc;
        uint256 offset;
    }
}
