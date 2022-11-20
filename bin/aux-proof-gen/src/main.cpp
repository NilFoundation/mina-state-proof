//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>

#ifndef __EMSCRIPTEN__
#include <boost/filesystem.hpp>
#include <boost/filesystem/string_file.hpp>
#include <boost/program_options.hpp>
#endif

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/alt_bn128.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_base_field.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verify_scalar.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/detail.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/verifier_index.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/verifier.hpp>

#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/verifier_index.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/circuit_json/json_serialization.hpp>
#include <nil/crypto3/circuit_json/json_deserialization.hpp>

#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>

#include <nil/mina/aux-proof-gen/ec_index_terms.hpp>
#include <nil/mina/aux-proof-gen/profiling_plonk_circuit.hpp>
#include <nil/mina/aux-proof-gen/proof_generate.hpp>

#include <fstream>

using namespace nil;
using namespace nil::crypto3;

using curve_type = nil::crypto3::algebra::curves::pallas;
using pallas_verifier_index_type = zk::snark::verifier_index<
    curve_type, nil::crypto3::zk::snark::arithmetic_sponge_params<curve_type::scalar_field_type::value_type>,
    nil::crypto3::zk::snark::arithmetic_sponge_params<curve_type::base_field_type::value_type>,
    nil::crypto3::zk::snark::kimchi_constant::COLUMNS, nil::crypto3::zk::snark::kimchi_constant::PERMUTES>;

inline std::vector<std::size_t> generate_step_list(const std::size_t r, const int max_step) {
    std::vector<std::size_t> step_list;
    std::size_t steps_sum = 0;
    while (steps_sum != r) {
        if (r - steps_sum <= max_step) {
            while (r - steps_sum != 1) {
                step_list.emplace_back(r - steps_sum - 1);
                steps_sum += step_list.back();
            }
            step_list.emplace_back(1);
            steps_sum += step_list.back();
        } else {
            step_list.emplace_back(max_step);
            steps_sum += step_list.back();
        }
    }
    return step_list;
}

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log, std::size_t max_step) {
    typename fri_type::params_type params;

    constexpr std::size_t expand_factor = 0;
    std::size_t r = degree_log - 1;

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

    params.r = r;
    params.D = domain_set;
    params.max_degree = (1 << degree_log) - 1;

    params.step_list = generate_step_list(r, max_step);

    return params;
}

template<typename Endianness, typename Proof>
void proof_print(const Proof &proof, std::string output_file) {
    using namespace nil::crypto3::marshalling;

    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using proof_marshalling_type = zk::snark::placeholder_proof<TTypeBase, Proof>;
    auto filled_placeholder_proof = crypto3::marshalling::types::fill_placeholder_proof<Endianness, Proof>(proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_placeholder_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_placeholder_proof.write(write_iter, cv.size());
    std::ofstream out;
    out.open(output_file);
    print_hex_byteblob(out, cv.cbegin(), cv.cend(), false);
}

#ifdef __EMSCRIPTEN__
extern "C" {
template<std::size_t EvalRounds>
const char *generate_proof_base(zk::snark::pickles_proof<nil::crypto3::algebra::curves::pallas> &pickles_proof,
                                pallas_verifier_index_type &pickles_index, const std::size_t fri_max_step,
                                std::string output_path) {
#else
template<std::size_t EvalRounds>
std::string generate_proof_base(std::string circuit_description_path, std::string public_input_path,
                                const std::size_t fri_max_step, std::string output_path) {
#endif
    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 0;
    constexpr static std::size_t max_poly_size = 1 << EvalRounds;    // 32768 in json
    constexpr static std::size_t srs_len = max_poly_size;
    constexpr static std::size_t eval_rounds = EvalRounds;    // 15 in json

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;
    constexpr static std::size_t lookup_table_size = 0;
    constexpr static bool use_lookup = false;

    constexpr static std::size_t batch_size = 1;

    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description =
        zk::components::kimchi_circuit_description<index_terms_list, witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    using component_type = zk::components::base_field<ArithmetizationType, curve_type, kimchi_params, commitment_params,
                                                      batch_size, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    using fq_output_type =
        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output;

    using fr_data_type = typename zk::components::binding<ArithmetizationType, BlueprintFieldType,
                                                          kimchi_params>::template fr_data<var, batch_size>;

    using fq_data_type =
        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::template fq_data<var>;

    std::vector<typename BlueprintFieldType::value_type> public_input = {};

    std::array<zk::components::kimchi_proof_base<BlueprintFieldType, kimchi_params>, batch_size> proofs;

    for (std::size_t batch_id = 0; batch_id < batch_size; batch_id++) {
        zk::components::kimchi_proof_base<BlueprintFieldType, kimchi_params> proof;
        proofs[batch_id] = proof;
    }

    zk::components::kimchi_verifier_index_base<curve_type, kimchi_params> verifier_index;

    fr_data_type fr_data_public;
    fq_data_type fq_data_public;

    public_input.push_back(3);
    for (std::size_t i = 0; i < fr_data_public.scalars.size(); i++) {
        var s(0, public_input.size() - 1, false, var::column_type::public_input);
        fr_data_public.scalars[i] = s;
    }

    typename component_type::params_type params = {proofs, verifier_index, fr_data_public, fq_data_public};

    using placeholder_params =
        zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, hash_type, hash_type, Lambda>;

    boost::filesystem::load_string_file(circuit_description_path + "/base_circuit.json", circuit_description_path);
    boost::filesystem::load_string_file(public_input_path + "/base_public_input.json", public_input_path);
    boost::json::value jv = boost::json::parse(circuit_description_path);
    boost::json::value jv_public_input = boost::json::parse(public_input_path);
    zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc_new =
        boost::json::value_to<zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams>>(
            jv.at("desc"));
    zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment_new =
        zk::generate_tmp(jv.at("public_assignment"), desc_new);
    zk::blueprint<ArithmetizationType> bp_new(
        boost::json::value_to<zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>(
            jv.at("bp")),
        desc_new);
    std::vector<typename BlueprintFieldType::value_type> public_input_new =
        boost::json::value_to<std::vector<typename BlueprintFieldType::value_type>>(jv_public_input.at("public_input"));

    proof_generate<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input_new, desc_new, bp_new, public_assignment_new,
        output_path + "/base_proof.data");

    std::string st;
#ifdef __EMSCRIPTEN__
    char *writable = new char[st.size() + 1];
    std::copy(st.begin(), st.end(), writable);
    return writable;
#else
    return st;
#endif
}

#ifdef __EMSCRIPTEN__
extern "C" {
template<std::size_t EvalRounds>
const char *generate_proof_scalar(zk::snark::pickles_proof<nil::crypto3::algebra::curves::pallas> &pickles_proof,
                                  pallas_verifier_index_type &pickles_index, const std::size_t fri_max_step,
                                  std::string output_path) {
#else
template<std::size_t EvalRounds>
std::string generate_proof_scalar(std::string circuit_description_path, std::string public_input_path,
                                  const std::size_t fri_max_step, std::string output_path) {
#endif
    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 1;
    constexpr static std::size_t max_poly_size = 1 << EvalRounds;    // 32768 in json
    constexpr static std::size_t srs_len = max_poly_size;
    constexpr static std::size_t eval_rounds = EvalRounds;    // 15 in json

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;
    constexpr static std::size_t lookup_table_size = 0;

    constexpr static std::size_t batch_size = 1;

    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description =
        zk::components::kimchi_circuit_description<index_terms_list, witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    using component_type =
        zk::components::verify_scalar<ArithmetizationType, curve_type, kimchi_params, commitment_params, batch_size, 0,
                                      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    using fq_output_type =
        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output;

    using fr_data_type = typename zk::components::binding<ArithmetizationType, BlueprintFieldType,
                                                          kimchi_params>::template fr_data<var, batch_size>;

    using fq_data_type =
        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::template fq_data<var>;

    std::vector<typename BlueprintFieldType::value_type> public_input = {0};

    std::array<zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds>, batch_size> proofs;

    for (std::size_t batch_id = 0; batch_id < batch_size; batch_id++) {
        zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;
        proofs[batch_id] = proof;
    }

    zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
    verifier_index.domain_size = max_poly_size;

    using fq_output_type =
        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output;

    fr_data_type fr_data_public;
    fq_data_type fq_data_public;
    std::array<fq_output_type, batch_size> fq_outputs;

    typename component_type::params_type params = {fr_data_public, fq_data_public, verifier_index, proofs, fq_outputs};

    boost::filesystem::load_string_file(circuit_description_path + "/scalar_circuit.json", circuit_description_path);
    boost::filesystem::load_string_file(public_input_path + "/scalar_public_input.json", public_input_path);

    boost::json::value jv = boost::json::parse(circuit_description_path);
    boost::json::value jv_public_input = boost::json::parse(public_input_path);
    zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc_new =
        boost::json::value_to<zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams>>(
            jv.at("desc"));
    zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment_new =
        zk::generate_tmp(jv.at("public_assignment"), desc_new);
    zk::blueprint<ArithmetizationType> bp_new(
        boost::json::value_to<zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>(
            jv.at("bp")),
        desc_new);
    std::vector<typename BlueprintFieldType::value_type> public_input_new =
        boost::json::value_to<std::vector<typename BlueprintFieldType::value_type>>(jv_public_input.at("public_input"));

    proof_generate<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input_new, desc_new, bp_new, public_assignment_new,
        output_path + "/scalar_proof.data");

    std::string st;
#ifdef __EMSCRIPTEN__
    char *writable = new char[st.size() + 1];
    std::copy(st.begin(), st.end(), writable);
    return writable;
#else
    return st;
#endif
}

void concatenate_proofs(std::string output_path) {
    std::string output_path_scalar = output_path + "scalar_proof.data";
    std::string output_path_base = output_path + "base_proof.data";
    std::string output_path_full = output_path + "full_proof.data";
    std::ifstream file_scalar(output_path_scalar, std::ios::binary);
    std::ifstream file_base(output_path_base, std::ios::binary);
    std::ofstream file_full(output_path_full, std::ios::binary);

    file_scalar.ignore(2);

    file_full << file_base.rdbuf();
    file_full << file_scalar.rdbuf();
}

template<std::size_t EvalRoundsScalar, std::size_t EvalRoundsBase>
void generate_proof_heterogenous(std::string circuit_description_path, std::string public_input_path,
                                 const std::size_t fri_max_step, std::string output_path) {

    generate_proof_scalar<EvalRoundsScalar>(circuit_description_path, public_input_path, fri_max_step, output_path);
    generate_proof_base<EvalRoundsBase>(circuit_description_path, public_input_path, fri_max_step, output_path);

    concatenate_proofs(output_path);
}

int main(int argc, char *argv[]) {
#ifndef __EMSCRIPTEN__

    std::string public_input, circuit_description, line, output;
    bool generate_scalar, generate_base, generate_heterogenous;
    std::size_t fri_max_step;

    boost::program_options::options_description options("Mina State Proof Auxiliary Proof Generator");
    // clang-format off
    options.add_options()("help,h", "Display help message")
            ("version,v", "Display version")
            ("output,o", boost::program_options::value<std::string>(&output), "Output file")
            ("public_input", boost::program_options::value<std::string>(), "Path for public input files")
            ("circuit_description", boost::program_options::value<std::string>(), "Path circuit description files")
            ("scalar_proof", boost::program_options::bool_switch(&generate_scalar)->default_value(false), "Generate scalar part of the circuit")
            ("base_proof", boost::program_options::bool_switch(&generate_base)->default_value(false), "Generate base part of the circuit")
            ("heterogenous_proof", boost::program_options::bool_switch(&generate_heterogenous)->default_value(false), "Generate mina state proof")
            ("max_step", boost::program_options::value<std::size_t>(&fri_max_step)->default_value(1), "Step for FRI folding (default 3)");

    boost::program_options::variables_map vm;
    boost::program_options::store(
        boost::program_options::command_line_parser(argc, argv).options(options).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help")) {
        std::cout << options << std::endl;
        return 0;
    }

    if (vm.count("public_input")) {
        public_input = vm["public_input"].as<std::string>();
    }

    if (vm.count("circuit_description")) {
        circuit_description = vm["circuit_description"].as<std::string>();
    }

    constexpr const std::size_t eval_rounds_scalar = 15;
    constexpr const std::size_t eval_rounds_base = 10;

    if (generate_base) {
        std::cout << std::string(generate_proof_base<eval_rounds_base>(circuit_description, public_input, fri_max_step, output)) <<
        std::endl;
    }
    if (generate_scalar) {
        std::cout << std::string(generate_proof_scalar<eval_rounds_scalar>(circuit_description, public_input, fri_max_step, output))
                  << std::endl;
    }
    if (generate_heterogenous) {
        generate_proof_heterogenous<eval_rounds_scalar, eval_rounds_base>(circuit_description, public_input, fri_max_step, output);
    }
#endif
}