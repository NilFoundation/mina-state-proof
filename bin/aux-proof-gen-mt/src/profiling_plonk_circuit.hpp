//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef ACTOR_PROFILING_COMPONENT_HPP
#define ACTOR_PROFILING_COMPONENT_HPP

#include <fstream>
#include <sstream>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/actor/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/actor/zk/blueprint/plonk.hpp>
#include <nil/actor/zk/assignment/plonk.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

namespace nil {
    namespace actor {
        template<typename FieldType, typename ArithmetizationParams, typename Hash, std::size_t Lambda>
        struct profiling_plonk_circuit {
            using placeholder_params = zk::snark::placeholder_params<FieldType, ArithmetizationParams, Hash, Hash, Lambda>;
            using types = zk::snark::detail::placeholder_policy<FieldType, placeholder_params>;
            using ArithmetizationType = zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
            using preprocessed_public_data_type = typename zk::snark::placeholder_public_preprocessor<
                    FieldType, placeholder_params>::preprocessed_data_type;

            template<typename FriType, typename ProofType>
            static void initialize_parameters(const FriType &fri_params, const ProofType &proof, const preprocessed_public_data_type &public_preprocessed_data) {
                std::cout << "modulus = " << FieldType::modulus << std::endl;
                std::cout << "fri_params.r = " << fri_params.r << std::endl;
                std::cout << "fri_params.max_degree = " << fri_params.max_degree << std::endl;
                std::cout << "fri_params.step_list = " << fri_params.step_list.size() << std::endl;
                for (auto i : fri_params.step_list) {
                    std::cout << i << ", ";
                }
                std::cout << std::endl;
                std::cout << "fri_params.q = 0 0 1 (now it's always x^2)" << std::endl;
                std::cout << "fri_params.D_omegas = ";
                for (const auto &dom : fri_params.D) {
                    std::cout << static_cast<nil::crypto3::math::basic_radix2_domain<FieldType> &>(*dom).omega.data
                              << ", ";
                }
                std::cout << std::endl;
                std::cout << "lpc_params.lambda = " << placeholder_params::batched_commitment_params_type::lambda
                          << std::endl;
                std::cout << "lpc_params.m = " << placeholder_params::batched_commitment_params_type::m << std::endl;
                std::cout << "common_data.omega = "
                          << static_cast<nil::crypto3::math::basic_radix2_domain<FieldType> &>(
                                 *public_preprocessed_data.common_data.basic_domain)
                                 .omega.data
                          << std::endl;
                std::cout << "max_leaf_size = "
                          << std::max({
                                 proof.eval_proof.witness.z.size(),
                                 proof.eval_proof.quotient.z.size(),
                                 proof.eval_proof.id_permutation.z.size(),
                                 proof.eval_proof.sigma_permutation.z.size(),
                                 proof.eval_proof.public_input.z.size(),
                                 proof.eval_proof.constant.z.size(),
                                 proof.eval_proof.selector.z.size(),
                                 proof.eval_proof.special_selectors.z.size(),
                             })
                          << std::endl;
                std::cout << "common_data.rows_amount = " << public_preprocessed_data.common_data.rows_amount << std::endl;
                std::cout << "common_data.columns_rotations ("
                          << public_preprocessed_data.common_data.columns_rotations.size() << " number) = {"
                          << std::endl;
                for (const auto &column_rotations : public_preprocessed_data.common_data.columns_rotations) {
                    std::cout << "[";
                    for (auto rot : column_rotations) {
                        std::cout << int(rot) << ", ";
                    }
                    std::cout << "]," << std::endl;
                }
                std::cout << "}" << std::endl;
            }

            template<typename Container, typename ContainerIt>
            static bool is_last_element(const Container &c, ContainerIt it) {
                return it == (std::cend(c) - 1);
            }

            static void print_variable(std::ostream &os, const zk::snark::plonk_variable<FieldType> &var,
                                       const preprocessed_public_data_type &public_preprocessed_data) {
                std::size_t rotation_idx =
                    std::find(std::cbegin(public_preprocessed_data.common_data.columns_rotations.at(var.index)),
                              std::cend(public_preprocessed_data.common_data.columns_rotations.at(var.index)),
                              var.rotation) -
                    std::begin(public_preprocessed_data.common_data.columns_rotations.at(var.index));
                os << "get_eval_i_by_rotation_idx(" << var.index << "," << rotation_idx
                   << ", mload(add(gate_params, ";
                if (zk::snark::plonk_variable<FieldType>::column_type::witness == var.type) {
                    os << "WITNESS_EVALUATIONS_OFFSET";
                }
                if (zk::snark::plonk_variable<FieldType>::column_type::constant == var.type) {
                    os << "CONSTANT_EVALUATIONS_OFFSET";
                }
                if (zk::snark::plonk_variable<FieldType>::column_type::public_input == var.type) {
                    os << "PUBLIC_INPUT_EVALUATIONS_OFFSET";
                }
                if (zk::snark::plonk_variable<FieldType>::column_type::selector == var.type) {
                    os << "SELECTOR_EVALUATIONS_OFFSET";
                }
                os << ")))";
            }

            template<typename Vars, typename VarsIt>
            static typename std::enable_if<
                std::is_same<zk::snark::plonk_variable<FieldType>,
                             typename std::iterator_traits<typename Vars::iterator>::value_type>::value>::type
                print_term(std::ostream &os,
                           const Vars &vars,
                           VarsIt it,
                           const preprocessed_public_data_type &public_preprocessed_data) {
                if (it != std::cend(vars)) {
                    if (!is_last_element(vars, it)) {
                        os << "mulmod(";
                    }
                    print_variable(os, *it, public_preprocessed_data);
                    if (!is_last_element(vars, it)) {
                        os << ",";
                        print_term(os, vars, it + 1, public_preprocessed_data);
                        os << ", modulus)";
                    }
                }
            }

            template<typename Terms, typename TermsIt>
            static typename std::enable_if<
                std::is_same<math::non_linear_term<zk::snark::plonk_variable<FieldType>>,
                             typename std::iterator_traits<typename Terms::iterator>::value_type>::value>::type
                print_terms(std::ostream &os,
                            const Terms &terms,
                            TermsIt it,
                            const preprocessed_public_data_type &public_preprocessed_data) {
                if (it != std::cend(terms)) {
                    os << "mstore("
                          "add(gate_params, CONSTRAINT_EVAL_OFFSET),"
                          "addmod("
                          "mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),";
//                    if (it->coeff != FieldType::value_type::one()) {
                    if (it->vars.size()) {
                        os << "mulmod(0x" << std::hex << it->coeff.data << std::dec << ",";
                    } else {
                        os << "0x" << std::hex << it->coeff.data << std::dec;
                    }
//                    }
                    print_term(os, it->vars, std::cbegin(it->vars), public_preprocessed_data);
//                    if (it->coeff != FieldType::value_type::one()) {
                        if (it->vars.size()) {
                            os << ",modulus)";
                        }
//                    }
                    os << ",modulus))" << std::endl;
                    print_terms(os, terms, it + 1, public_preprocessed_data);
                }
            }

            static void
                print_constraint(std::ostream &os,
                                 const typename zk::snark::plonk_constraint<FieldType> &constraint,
                                 const preprocessed_public_data_type &public_preprocessed_data) {
                os << "mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)" << std::endl;
                print_terms(os, constraint.terms, std::cbegin(constraint.terms), public_preprocessed_data);
            }

            static void print_gate_evaluation(std::ostream &os) {
                os << "mstore(add(gate_params, GATE_EVAL_OFFSET),addmod("
                      "mload(add(gate_params, GATE_EVAL_OFFSET)),"
                      "mulmod(mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))"
                   << std::endl;
            }

            static void print_theta_acc(std::ostream &os) {
                os << "theta_acc := mulmod(theta_acc,mload(add(gate_params, THETA_OFFSET)),modulus)" << std::endl;
            }

            static void print_selector(std::ostream &os,
                                       const zk::snark::plonk_gate<
                                           FieldType, zk::snark::plonk_constraint<FieldType>> &gate) {
                os << "mstore(add(gate_params, GATE_EVAL_OFFSET),mulmod(mload(add(gate_params, GATE_EVAL_OFFSET)),"
                      "get_selector_i("
                   << gate.selector_index
                   << ",mload(add(gate_params, SELECTOR_EVALUATIONS_OFFSET))),modulus))"
                   << std::endl;
            }

            static void print_argument_evaluation(std::ostream &os) {
                os << "gates_evaluation := addmod(gates_evaluation,mload(add(gate_params, GATE_EVAL_OFFSET)),modulus)"
                   << std::endl;
            }

            static void print_gate(std::ostream &os,
                                   const zk::snark::plonk_gate<
                                       FieldType, zk::snark::plonk_constraint<FieldType>> &gate,
                                   const preprocessed_public_data_type &public_preprocessed_data) {
                os << "mstore(add(gate_params, GATE_EVAL_OFFSET), 0)" << std::endl;
                for (auto &constraint : gate.constraints) {
                    print_constraint(os, constraint, public_preprocessed_data);
                    print_gate_evaluation(os);
                    print_theta_acc(os);
                }
                print_selector(os, gate);
                print_argument_evaluation(os);
            }

            static void process(std::ostream &os, const zk::blueprint<ArithmetizationType> &bp,
                                const preprocessed_public_data_type &public_preprocessed_data) {
                for (const auto &gate : bp.gates()) {
                    print_gate(os, gate, public_preprocessed_data);
                }
            }

            template <typename ParamsType>
            static void process_split(std::ostream &os, zk::snark::plonk_constraint_system<FieldType, typename ParamsType::arithmetization_params>
                                                            &bp,
                                      const preprocessed_public_data_type &public_preprocessed_data) {
                std::size_t gate_index = 0;
                for (const auto &gate : bp.gates()) {
                    std::ofstream gate_out;
                    gate_out.open("gate" + std::to_string(gate_index) + ".txt");
                    print_gate(gate_out, gate, public_preprocessed_data);
                    ++gate_index;
                }
            }
        };
    }    // namespace actor
}    // namespace nil

#endif    // ACTOR_PROFILING_COMPONENT_HPP
