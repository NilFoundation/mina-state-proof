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

#include <boost/random.hpp>
#include <boost/random/random_device.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>

#ifndef __EMSCRIPTEN__
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#endif

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/alt_bn128.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verify_scalar.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/binding.hpp>

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

//#include <nil/marshalling/endianness.hpp>
//#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>

#include <fstream>

using namespace nil;
using namespace nil::crypto3;

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log) {
    typename fri_type::params_type params;

    constexpr std::size_t expand_factor = 0;
    std::size_t r = degree_log - 1;

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

    params.r = r;
    params.D = domain_set;
    params.max_degree = (1 << degree_log) - 1;

    return params;
}

template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    os << "0x";
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::endl << std::dec;
}
/*
template<typename Endianness, typename RedshiftProof>
std::string marshalling_to_blob(const RedshiftProof &proof) {
    using namespace crypto3::marshalling;

    auto filled_placeholder_proof = types::fill_placeholder_proof<RedshiftProof, Endianness>(proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_placeholder_proof.length(), 0x00);
    auto write_iter = cv.begin();
    if (filled_placeholder_proof.write(write_iter, cv.size()) == nil::marshalling::status_type::success) {
        std::stringstream st;
        print_byteblob(st, cv.cbegin(), cv.cend());
        return st.str();
    } else {
        return {};
    }
}
*/
template<typename Iterator>
multiprecision::cpp_int get_cppui256(Iterator it) {
    BOOST_ASSERT(it->second.template get_value<std::string>() != "");
    return multiprecision::cpp_int(it->second.template get_value<std::string>());
}

zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> make_proof(boost::property_tree::ptree root) {
    zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> proof;
    size_t i = 0;
    std::string base_path = "data.genesisBlock.protocolStateProof.json.proof.";

    i = 0;
    //data.genesisBlock.protocolStateProof.json.proof.messages.w_comm[0][0][0]
    //data.genesisBlock.protocolStateProof.json.statement.proof_state.deferred_values.bulletproof_challenges[0].prechallenge.inner[0]
    for (auto &row : root.get_child(base_path + "messages.w_comm")) {
        auto it = row.second.get_child("").begin()->second.get_child("").begin();
        proof.commitments.w_comm[i].unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
        ++i;
    }
    auto it = root.get_child(base_path + "messages.z_comm").begin()->second.get_child("").begin();
    proof.commitments.z_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));

    it = root.get_child(base_path + "messages.t_comm").begin()->second.get_child("").begin();
    proof.commitments.t_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    //    proof.commitments.lookup;    // TODO: where it is?

    i = 0;
    for (auto &row : root.get_child(base_path + "openings.proof.lr")) {
        auto it0 = row.second.begin()->second.get_child("").begin();
        auto it1 = row.second.begin();
        it1++;
        it1 = it1->second.begin();
        proof.proof.lr.push_back({{get_cppui256(it0++), get_cppui256(it0)}, {get_cppui256(it1++), get_cppui256(it1)}});
        ++i;
    }
    it = root.get_child(base_path + "openings.proof.delta").begin();
    proof.proof.delta = {get_cppui256(it++), get_cppui256(it)};
    it = root.get_child(base_path + "openings.proof.sg").begin();
    proof.proof.sg = {get_cppui256(it++), get_cppui256(it)};

    proof.proof.z1 = multiprecision::cpp_int(root.get<std::string>(base_path + "openings.proof.z_1"));
    proof.proof.z2 = multiprecision::cpp_int(root.get<std::string>(base_path + "openings.proof.z_2"));

    std::size_t ev_i = 0;
    for (auto &evals_it : root.get_child(base_path + "openings.evals")) {

        i = 0;
        for (auto &row : evals_it.second.get_child("w")) {
            proof.evals[ev_i].w[i] = get_cppui256(row.second.begin());
        }

        proof.evals[ev_i].z = get_cppui256(evals_it.second.get_child("z").begin());

        i = 0;
        for (auto &row : evals_it.second.get_child("s")) {
            proof.evals[ev_i].s[i] = get_cppui256(row.second.begin());
        }
        proof.evals[ev_i].generic_selector = get_cppui256(evals_it.second.get_child("generic_selector").begin());
        proof.evals[ev_i].poseidon_selector = get_cppui256(evals_it.second.get_child("poseidon_selector").begin());

        ev_i++;
    }

    proof.ft_eval1 = multiprecision::cpp_int(root.get<std::string>(base_path + "openings.ft_eval1"));

    std::string public_input_path = "data.genesisBlock.protocolStateProof.json.prev_evals.evals";

    for (auto &evals_it : root.get_child(public_input_path)) {
        //data.genesisBlock.protocolStateProof.json.prev_evals.evals[0].public_input
        proof.public_input.emplace_back(multiprecision::cpp_int(evals_it.second.get_child("").begin()->second.get_value<std::string>("public_input")));
    }
    std::string challenges_path = "data.genesisBlock.protocolStateProof.json.statement.proof_state.deferred_values.bulletproof_challenges";

    //data.genesisBlock.protocolStateProof.json.statement.proof_state.deferred_values.bulletproof_challenges[0].prechallenge.inner[0]
    for (auto &evals_it : root.get_child(challenges_path)) {
        for (auto &tt : evals_it.second.get_child("prechallenge.inner")) {
//            std::cout << tt.second.get_value<std::string>("") << std::endl;
//            proof.prev_challenges.emplace_back(std::make_pair())
        }
    }
    return proof;
}

zk::snark::verifier_index<nil::crypto3::algebra::curves::vesta>
    make_verify_index(boost::property_tree::ptree root, boost::property_tree::ptree const_root) {
    zk::snark::verifier_index<nil::crypto3::algebra::curves::vesta> ver_index;
    size_t i = 0;
    ver_index.domain = {
        root.get<std::size_t>("data.blockchainVerificationKey.index.domain.log_size_of_group"),
        multiprecision::cpp_int(root.get<std::string>("data.blockchainVerificationKey.index.domain.group_gen"))};

    ver_index.max_poly_size = root.get<std::size_t>("data.blockchainVerificationKey.index.max_poly_size");
    ver_index.max_quot_size = root.get<std::size_t>("data.blockchainVerificationKey.index.max_quot_size");
    //    ver_index.srs = root.get<std::string>("data.blockchainVerificationKey.index.srs");    // TODO: null
    i = 0;
    for (auto &row : root.get_child("data.blockchainVerificationKey.commitments.sigma_comm")) {
        auto it = row.second.begin();
        ver_index.sigma_comm[i].unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
        ++i;
    }

    i = 0;
    for (auto &row : root.get_child("data.blockchainVerificationKey.commitments.coefficients_comm")) {
        auto it = row.second.begin();
        ver_index.coefficients_comm[i].unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
        ++i;
    }
    auto it = root.get_child("data.blockchainVerificationKey.commitments.generic_comm").begin();
    ver_index.generic_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));

    it = root.get_child("data.blockchainVerificationKey.commitments.psm_comm").begin();
    ver_index.psm_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    it = root.get_child("data.blockchainVerificationKey.commitments.complete_add_comm").begin();
    ver_index.complete_add_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    it = root.get_child("data.blockchainVerificationKey.commitments.mul_comm").begin();
    ver_index.mul_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    it = root.get_child("data.blockchainVerificationKey.commitments.emul_comm").begin();
    ver_index.emul_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    it = root.get_child("data.blockchainVerificationKey.commitments.endomul_scalar_comm").begin();
    ver_index.endomul_scalar_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));

    // TODO: null in example
    //    i = 0;
    //    for (auto &row : root.get_child("data.blockchainVerificationKey.commitments.chacha_comm")) {
    //        auto it = row.second.begin();
    //        ver_index.chacha_comm[i].unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    //        ++i;
    //    }
    i = 0;
    for (auto &row : root.get_child("data.blockchainVerificationKey.index.shifts")) {
        ver_index.shifts[i] = multiprecision::cpp_int(row.second.get_value<std::string>());
        ++i;
    }

    // Polynomial in coefficients form
    // Const
    ver_index.zkpm = {0x2C46205451F6C3BBEA4BABACBEE609ECF1039A903C42BFF639EDC5BA33356332_cppui256,
                      0x1764D9CB4C64EBA9A150920807637D458919CB6948821F4D15EB1994EADF9CE3_cppui256,
                      0x0140117C8BBC4CE4644A58F7007148577782213065BB9699BF5C391FBE1B3E6D_cppui256,
                      0x0000000000000000000000000000000000000000000000000000000000000001_cppui256};
    ver_index.w = multiprecision::cpp_int(const_root.get<std::string>("verify_index.w"));
    ver_index.endo = multiprecision::cpp_int(const_root.get<std::string>("verify_index.endo"));

    // ver_index.lookup_index = root.get_child("data.blockchainVerificationKey.index.lookup_index"); // TODO: null
    // ver_index.linearization;       // TODO: where it is?
    ver_index.powers_of_alpha.next_power = 24;

    for (auto &row : const_root.get_child("verify_index.fr_sponge_params.round_constants")) {
        auto it = row.second.begin();
        ver_index.fr_sponge_params.round_constants.push_back(
            {get_cppui256(it++), get_cppui256(it++), get_cppui256(it)});
    }
    for (auto &row : const_root.get_child("verify_index.fr_sponge_params.mds")) {
        auto it = row.second.begin();
        ver_index.fr_sponge_params.mds.push_back({get_cppui256(it++), get_cppui256(it++), get_cppui256(it)});
    }

    for (auto &row : const_root.get_child("verify_index.fq_sponge_params.round_constants")) {
        auto it = row.second.begin();
        ver_index.fq_sponge_params.round_constants.push_back(
            {get_cppui256(it++), get_cppui256(it++), get_cppui256(it)});
    }
    for (auto &row : const_root.get_child("verify_index.fq_sponge_params.mds")) {
        auto it = row.second.begin();
        ver_index.fq_sponge_params.mds.push_back({get_cppui256(it++), get_cppui256(it++), get_cppui256(it)});
    }
    return ver_index;
}

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType, std::size_t EvalRounds>
void prepare_proof(zk::snark::pickles_proof<CurveType> &original_proof,
                   zk::components::kimchi_proof_scalar<BlueprintFieldType, KimchiParamsType, EvalRounds> &circuit_proof,
                   std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    // eval_proofs
    for (std::size_t point_idx = 0; point_idx < 2; point_idx++) {
        // w
        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
            public_input.push_back(original_proof.evals[point_idx].w[i]);
            circuit_proof.proof_evals[point_idx].w[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // z
        public_input.push_back(original_proof.evals[point_idx].z);
        circuit_proof.proof_evals[point_idx].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // s
        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
            public_input.push_back(original_proof.evals[point_idx].s[i]);
            circuit_proof.proof_evals[point_idx].s[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // lookup
        if (KimchiParamsType::use_lookup) {
            // TODO
        }
        // generic_selector
        public_input.push_back(original_proof.evals[point_idx].generic_selector);
        circuit_proof.proof_evals[point_idx].generic_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        // poseidon_selector
        public_input.push_back(original_proof.evals[point_idx].poseidon_selector);
        circuit_proof.proof_evals[point_idx].poseidon_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t i = 0; i < KimchiParamsType::public_input_size; i++) {
        public_input.push_back(original_proof.public_input[i]);
        circuit_proof.public_input[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t i = 0; i < KimchiParamsType::prev_challenges_size; i++) {
        for (std::size_t j = 0; j < EvalRounds; j++) {
            public_input.push_back(original_proof.prev_challenges[i].first[j]);
            circuit_proof.prev_challenges[i][j] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }

    // ft_eval
    public_input.push_back(original_proof.ft_eval1);
    circuit_proof.ft_eval = var(0, public_input.size() - 1, false, var::column_type::public_input);
}

template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
         std::size_t Lambda, typename FunctorResultCheck, typename PublicInput,
         typename std::enable_if<
             std::is_same<typename BlueprintFieldType::value_type,
                          typename std::iterator_traits<typename PublicInput::iterator>::value_type>::value,
             bool>::type = true>
auto prepare_component(typename ComponentType::params_type params, const PublicInput &public_input,
                       const FunctorResultCheck &result_check) {

    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using component_type = ComponentType;

    zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

    zk::blueprint<ArithmetizationType> bp(desc);
    zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
    zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);
    zk::blueprint_assignment_table<ArithmetizationType> assignment_bp(private_assignment, public_assignment);

    std::size_t start_row = zk::components::allocate<component_type>(bp);
    if (public_input.size() > component_type::rows_amount) {
        bp.allocate_rows(public_input.size() - component_type::rows_amount);
    }

    for (std::size_t i = 0; i < public_input.size(); i++) {
        auto allocated_pi = assignment_bp.allocate_public_input(public_input[i]);
    }

    zk::components::generate_circuit<component_type>(bp, public_assignment, params, start_row);
    typename component_type::result_type component_result =
        component_type::generate_assignments(assignment_bp, params, start_row);
    std::bind(result_check, assignment_bp, component_result);

    assignment_bp.padding();
    std::cout << "Usable rows: " << desc.usable_rows_amount << std::endl;
    std::cout << "Padded rows: " << desc.rows_amount << std::endl;

    zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(private_assignment,
                                                                                             public_assignment);

    using placeholder_params =
        zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;
    using types = zk::snark::detail::placeholder_policy<BlueprintFieldType, placeholder_params>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType, typename placeholder_params::merkle_hash_type,
                                                   typename placeholder_params::transcript_hash_type, 2, 1>;

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

    std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

    typename zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params>::preprocessed_data_type
        public_preprocessed_data =
            zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params>::process(
                bp, public_assignment, desc, fri_params, permutation_size);
    typename zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params>::preprocessed_data_type
        private_preprocessed_data =
            zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params>::process(
                bp, private_assignment, desc, fri_params);

    return std::make_tuple(desc, bp, fri_params, assignments, public_preprocessed_data, private_preprocessed_data);
}

#ifdef __EMSCRIPTEN__
extern "C" {

const char *generate_proof(zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> *pickles_proof) {
#else
std::string generate_proof(zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> *pickles_proof) {
#endif
    using curve_type = algebra::curves::vesta;
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
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t alpha_powers_n = 5;
    constexpr static std::size_t public_input_size = 2;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;
    constexpr static std::size_t lookup_table_size = 1;
    constexpr static bool use_lookup = false;

    constexpr static std::size_t srs_len = 10;
    constexpr static std::size_t batch_size = 1;

    constexpr static const std::size_t index_terms = 0;
    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using kimchi_params =
        zk::components::kimchi_params_type<commitment_params, witness_columns, perm_size, use_lookup, lookup_table_size,
                                           alpha_powers_n, public_input_size, index_terms, prev_chal_size>;

    using fq_output_type =
        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output;

    using fr_data_type = typename zk::components::binding<ArithmetizationType, BlueprintFieldType,
                                                          kimchi_params>::fr_data<var, batch_size>;

    using fq_data_type =
        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_data<var>;

    zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
    typename BlueprintFieldType::value_type omega =
        0x1B1A85952300603BBF8DD3068424B64608658ACBB72CA7D2BB9694ADFA504418_cppui256;
    std::size_t domain_size = 128;
    verifier_index.domain_size = domain_size;
    verifier_index.omega = var(0, 0, false, var::column_type::public_input);

    using component_type =
        zk::components::verify_scalar<ArithmetizationType, curve_type, kimchi_params, commitment_params, batch_size, 0,
                                      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type joint_combiner = 0;
    typename BlueprintFieldType::value_type beta = 0;
    typename BlueprintFieldType::value_type gamma = 0;
    typename BlueprintFieldType::value_type alpha =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type fq_digest =
        0x01D4E77CCD66755BDDFDBB6E4E8D8D17A6708B9CB56654D12070BD7BF4A5B33B_cppui256;

    std::vector<typename BlueprintFieldType::value_type> public_input = {omega};

    std::array<zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds>, batch_size> proofs;

    std::array<fq_output_type, batch_size> fq_outputs;

    for (std::size_t batch_id = 0; batch_id < batch_size; batch_id++) {
        zk::snark::pickles_proof<curve_type> kimchi_proof = pickles_proof[batch_id];

        zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;

        prepare_proof<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);

        fq_output_type fq_output;
        std::array<var, eval_rounds> challenges;
        for (std::size_t j = 0; j < eval_rounds; j++) {
            public_input.emplace_back(10);
            challenges[j] = var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        fq_output.challenges = challenges;

        // joint_combiner
        public_input.emplace_back(0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256);
        fq_output.joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // beta
        public_input.emplace_back(0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256);
        fq_output.beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // gamma
        public_input.emplace_back(0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256);
        fq_output.gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // alpha
        public_input.push_back(alpha);
        fq_output.alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // zeta
        public_input.push_back(zeta);
        fq_output.zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // fq_digest
        public_input.push_back(fq_digest);
        fq_output.fq_digest = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // c
        public_input.emplace_back(250);
        fq_output.c = var(0, public_input.size() - 1, false, var::column_type::public_input);

        fq_outputs[batch_id] = fq_output;
    }

    fr_data_type fr_data_public;
    fq_data_type fq_data_public;

    typename component_type::params_type params = {fr_data_public, fq_data_public, verifier_index, proofs, fq_outputs};

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    //using Endianness = nil::marshalling::option::big_endian;

    using placeholder_params =
        zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, hash_type, hash_type, Lambda>;

    auto [desc, bp, fri_params, assignments, public_preprocessed_data, private_preprocessed_data] =
        prepare_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
            params, public_input, result_check);

    auto proof = zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params>::process(
        public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

    bool verifier_res = zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params>::process(
        public_preprocessed_data, proof, bp, fri_params);

    //std::string st = marshalling_to_blob<Endianness>(proof);
    std::string st;
#ifdef __EMSCRIPTEN__
    char *writable = new char[st.size() + 1];
    std::copy(st.begin(), st.end(), writable);
    return writable;
#else
    return st;
#endif
}

zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> parse_proof(const char *kimchi) {
    std::stringstream ss1;
    ss1 << kimchi;
    boost::property_tree::ptree root, const_root;
    // Load the json file in this ptree
    boost::property_tree::read_json(ss1, root);

    return make_proof(root);
}

int parse_pconst(const char *vk, const char *vk_const) {
    std::stringstream ss1, ss2;
    ss1 << vk;
    ss2 << vk_const;
    boost::property_tree::ptree root, const_root;
    // Load the json file in this ptree
    boost::property_tree::read_json(ss1, root);
    boost::property_tree::read_json(ss2, const_root);

    zk::snark::verifier_index<nil::crypto3::algebra::curves::vesta> ver_index = make_verify_index(root, const_root);
    return 0;
}

#ifdef __EMSCRIPTEN__
}
#endif

int main(int argc, char *argv[]) {
#ifndef __EMSCRIPTEN__

    std::string vp_input, vi_input, vi_const_input, line;

    boost::program_options::options_description options("Mina State Proof Auxiliary Proof Generator");
    // clang-format off
    options.add_options()("help,h", "Display help message")
            ("version,v", "Display version")
            ("output,o", boost::program_options::value<std::string>(),"Output file")
            ("vp_input", boost::program_options::value<std::string>(), "Input proof file")
            ("vi_input", boost::program_options::value<std::string>(), "Input index file")
            ("vi_const_input", boost::program_options::value<std::string>(), "Input const index file");
    // clang-format on

    boost::program_options::positional_options_description p;
    p.add("vp_input", 1);
    //    p.add("vi_input", 1);
    //    p.add("vi_const_input", 1);

    boost::program_options::variables_map vm;
    boost::program_options::store(
        boost::program_options::command_line_parser(argc, argv).options(options).positional(p).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help")) {
        std::cout << options << std::endl;
        return 0;
    }

    if (vm.count("vp_input")) {
        if (boost::filesystem::exists(vm["vp_input"].as<std::string>())) {
            boost::filesystem::load_string_file(vm["vp_input"].as<std::string>(), vp_input);
        }
    }

    if (vm.count("vi_input")) {
        if (boost::filesystem::exists(vm["vi_input"].as<std::string>())) {
            boost::filesystem::load_string_file(vm["vi_input"].as<std::string>(), vi_input);
        }
    }

    if (vm.count("vi_const_input")) {
        if (boost::filesystem::exists(vm["vi_const_input"].as<std::string>())) {
            boost::filesystem::load_string_file(vm["vi_const_input"].as<std::string>(), vi_const_input);
        }
    }
    //    else {
    //        while (std::getline(std::cin, line)) {
    //            string += line + "\n";
    //        }
    //    }
    zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> proof = parse_proof(vp_input.c_str());
    parse_pconst(vi_input.c_str(), vi_const_input.c_str());
    std::cout << std::string(generate_proof(&proof)) << std::endl;
#endif
}
