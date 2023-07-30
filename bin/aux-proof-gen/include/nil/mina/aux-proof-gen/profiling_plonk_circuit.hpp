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

#ifndef CRYPTO3_PROFILING_COMPONENT_HPP
#define CRYPTO3_PROFILING_COMPONENT_HPP

#include <fstream>
#include <sstream>

#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint_mc/blueprint/plonk.hpp>
#include <nil/blueprint_mc/assignment/plonk.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

namespace nil {
    namespace crypto3 {
        template<typename FieldType, typename ArithmetizationParams, typename Hash, std::size_t Lambda>
        struct profiling_plonk_circuit {
            using placeholder_params = zk::snark::placeholder_params<FieldType, ArithmetizationParams, Hash, Hash, Lambda>;
            using types = zk::snark::detail::placeholder_policy<FieldType, placeholder_params>;
            using ArithmetizationType = zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
            using preprocessed_public_data_type = typename zk::snark::placeholder_public_preprocessor<
                    FieldType, placeholder_params>::preprocessed_data_type;
/*
            template<typename FriType>
            static void initialize_parameters(const FriType &fri_params, const preprocessed_public_data_type &public_preprocessed_data) {
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
                                proof.eval_proof.combined_value.z[0].size(),
                                proof.eval_proof.combined_value.z[1].size(),
                                proof.eval_proof.combined_value.z[2].size(),
                                proof.eval_proof.combined_value.z[3].size(),
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
*/
            template<typename Container, typename ContainerIt>
            static bool is_last_element(const Container &c, ContainerIt it) {
                return it == (std::cend(c) - 1);
            }

            static void print_variable(std::ostream &os, const nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type> &var,
                                       const preprocessed_public_data_type &public_preprocessed_data) {
                std::size_t rotation_idx = std::distance(
                    public_preprocessed_data.common_data.columns_rotations.at(var.index).begin(),
                    public_preprocessed_data.common_data.columns_rotations.at(var.index).find(var.rotation));
                os << "get_eval_i_by_rotation_idx(" << var.index << "," << rotation_idx
                   << ", mload(add(gate_params, ";
                if (zk::snark::plonk_variable<typename FieldType::value_type>::column_type::witness == var.type) {
                    os << "get_witness_i_by_rotation_idx(" << var.index << "," << rotation_idx << ", gate_params)";
                }
                if (zk::snark::plonk_variable<typename FieldType::value_type>::column_type::constant == var.type) {
                    os << "get_constant_i_by_rotation_idx(" << var.index << "," << rotation_idx << ", gate_params)";
                }
                if (zk::snark::plonk_variable<typename FieldType::value_type>::column_type::public_input == var.type) {
                    os << "get_public_input_i(" << var.index << "," << rotation_idx << ", gate_params)";
                }
                if (zk::snark::plonk_variable<typename FieldType::value_type>::column_type::selector == var.type) {
                    os << "get_selector_i("<< var.index << ", gate_params)";
                }
                os << ")))";
            }

            template<typename Vars>
            static void print_term(std::ostream &os,
                           const Vars &vars,
                           const preprocessed_public_data_type &public_preprocessed_data) {
                for( auto it = std::cbegin(vars); it != std::end(vars); it++){
                    os << "terms:=mulmod(terms, ";
                    print_variable(os, *it, public_preprocessed_data);
                    os << ", modulus)" << std::endl;
                }
            }

            template<typename Terms>
            static void print_terms(std::ostream &os,
                            const Terms &terms,
                            const preprocessed_public_data_type &public_preprocessed_data) {
                for( auto it = std::cbegin(terms); it != std::cend(terms); it++ ){
                    os << "terms:=0x" << std::hex << it->get_coeff().data << std::dec << std::endl;
                    print_term(os, it->get_vars(), public_preprocessed_data);
                    os << "mstore("
                          "add(gate_params, CONSTRAINT_EVAL_OFFSET),"
                          "addmod("
                          "mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),";
                    os << "terms";
                    os << ",modulus))" << std::endl;
                }
            }

            static void
                print_constraint(std::ostream &os,
                                 const typename nil::crypto3::zk::snark::plonk_constraint<FieldType> &constraint,
                                 const preprocessed_public_data_type &public_preprocessed_data) {
                os << "mstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)" << std::endl;
                // Convert constraint expression to non_linear_combination.
                math::expression_to_non_linear_combination_visitor<nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>> visitor;
                auto comb = visitor.convert(constraint);
                print_terms(os, comb.terms, public_preprocessed_data);
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
                                       const nil::crypto3::zk::snark::plonk_gate<
                                           FieldType, nil::crypto3::zk::snark::plonk_constraint<FieldType>> &gate) {
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
                                   const nil::crypto3::zk::snark::plonk_gate<
                                       FieldType, nil::crypto3::zk::snark::plonk_constraint<FieldType>> &gate,
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

            static void process(std::ostream &os, const nil::blueprint_mc::blueprint<ArithmetizationType> &bp,
                                const preprocessed_public_data_type &public_preprocessed_data) {
                for (const auto &gate : bp.gates()) {
                    print_gate(os, gate, public_preprocessed_data);
                }
            }

//            template <typename ParamsType>
            static void process_split(std::ostream &os, zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>
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
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PROFILING_COMPONENT_HPP
