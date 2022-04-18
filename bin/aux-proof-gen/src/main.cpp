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
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_endo_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/pickles/verifier_index.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/redshift/proof.hpp>

#include <fstream>

using namespace nil;
using namespace nil::crypto3;

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    constexpr std::size_t expand_factor = 0;
    std::size_t r = degree_log - 1;

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        zk::commitments::detail::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

    params.r = r;
    params.D = domain_set;
    params.q = q;
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

template<typename Endianness, typename RedshiftProof>
std::string marshalling_to_blob(const RedshiftProof &proof) {
    using namespace crypto3::marshalling;

    auto filled_redshift_proof = types::fill_redshift_proof<RedshiftProof, Endianness>(proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_redshift_proof.length(), 0x00);
    auto write_iter = cv.begin();
    if (filled_redshift_proof.write(write_iter, cv.size()) == nil::marshalling::status_type::success) {
        std::stringstream st;
        print_byteblob(st, cv.cbegin(), cv.cend());
        return st.str();
    } else {
        return {};
    }
}

template<typename Iterator>
multiprecision::cpp_int get_cppui256(Iterator it) {
    BOOST_ASSERT(it->second.template get_value<std::string>() != "");
    return multiprecision::cpp_int(it->second.template get_value<std::string>());
}

zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> make_proof(boost::property_tree::ptree root) {
    zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> proof;
    size_t i = 0;
    std::string base_path = "protocolStateProof.json.proof.";

    auto best_chain = *root.get_child("data.bestChain").begin();
    i = 0;
    for (auto &row : best_chain.second.get_child(base_path + "messages.w_comm")) {
        auto it = row.second.get_child("").begin()->second.get_child("").begin();
        proof.commitments.w_comm[i].unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
        ++i;
    }
    auto it = best_chain.second.get_child(base_path + "messages.z_comm").begin()->second.get_child("").begin();
    proof.commitments.z_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));

    it = best_chain.second.get_child(base_path + "messages.t_comm").begin()->second.get_child("").begin();
    proof.commitments.t_comm.unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    //    proof.commitments.lookup;    // TODO: where it is?

    i = 0;
    for (auto &row : best_chain.second.get_child(base_path + "openings.proof.lr")) {
        auto it0 = row.second.begin()->second.get_child("").begin();
        auto it1 = row.second.begin();
        it1++;
        it1 = it1->second.begin();
        proof.proof.lr.push_back({{get_cppui256(it0++), get_cppui256(it0)}, {get_cppui256(it1++), get_cppui256(it1)}});
        ++i;
    }
    it = best_chain.second.get_child(base_path + "openings.proof.delta").begin();
    proof.proof.delta = {get_cppui256(it++), get_cppui256(it)};
    it = best_chain.second.get_child(base_path + "openings.proof.sg").begin();
    proof.proof.sg = {get_cppui256(it++), get_cppui256(it)};

    proof.proof.z1 = multiprecision::cpp_int(best_chain.second.get<std::string>(base_path + "openings.proof.z_1"));
    proof.proof.z2 = multiprecision::cpp_int(best_chain.second.get<std::string>(base_path + "openings.proof.z_2"));

    std::size_t ev_i = 0;
    for (auto &evals_it : best_chain.second.get_child(base_path + "openings.evals")) {

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

    proof.ft_eval1 = multiprecision::cpp_int(best_chain.second.get<std::string>(base_path + "openings.ft_eval1"));
    //            // public
    //            std::vector<typename CurveType::scalar_field_type::value_type> public_p; // TODO: where it is?
    //
    //            // Previous challenges
    //            std::vector<
    //                std::tuple<std::vector<typename CurveType::scalar_field_type::value_type>, commitment_scheme>>
    //                prev_challenges; // TODO: where it is?
    return proof;
}

zk::snark::verifier_index<nil::crypto3::algebra::curves::vesta>
    make_verify_index(boost::property_tree::ptree root, boost::property_tree::ptree const_root) {
    zk::snark::verifier_index<nil::crypto3::algebra::curves::vesta> ver_index;
    size_t i = 0;
    ver_index.domain = {const_root.get<std::size_t>("verify_index.domain.log_size_of_group"),
                        multiprecision::cpp_int(const_root.get<std::string>("verify_index.domain.group_gen"))};

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

extern "C" {

const char *proof_gen() {
    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using arithmetization_params =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    typedef zk::snark::plonk_constraint_system<BlueprintFieldType, arithmetization_params> arithmetization_type;

    typedef zk::components::curve_element_unified_addition<arithmetization_type, curve_type, 0, 1, 2, 3, 4, 5, 6, 7, 8,
                                                           9, 10>
        component_type;

    auto P = algebra::random_element<curve_type::template g1_type<>>().to_affine();
    auto Q = algebra::random_element<curve_type::template g1_type<>>().to_affine();

    typename component_type::params_type params = {
        {zk::snark::plonk_variable<BlueprintFieldType>(
             0, 1, false, zk::snark::plonk_variable<BlueprintFieldType>::column_type::public_input),
         zk::snark::plonk_variable<BlueprintFieldType>(
             0, 2, false, zk::snark::plonk_variable<BlueprintFieldType>::column_type::public_input)},
        {zk::snark::plonk_variable<BlueprintFieldType>(
             0, 3, false, zk::snark::plonk_variable<BlueprintFieldType>::column_type::public_input),
         zk::snark::plonk_variable<BlueprintFieldType>(
             0, 4, false, zk::snark::plonk_variable<BlueprintFieldType>::column_type::public_input)}};

    std::vector<typename BlueprintFieldType::value_type> public_input = {0, P.X, P.Y, Q.X, Q.Y};

    typename component_type::allocated_data_type allocated;
    zk::snark::plonk_table_description<BlueprintFieldType, arithmetization_params> desc;

    zk::blueprint<arithmetization_type> bp(desc);
    zk::blueprint_private_assignment_table<arithmetization_type> private_assignment(desc);
    zk::blueprint_public_assignment_table<arithmetization_type> public_assignment(desc);
    zk::blueprint_assignment_table<arithmetization_type> assignment_bp(private_assignment, public_assignment);

    std::size_t start_row = component_type::allocate_rows(bp);
    component_type::generate_circuit(bp, assignment_bp, params, allocated, start_row);
    component_type::generate_assignments(assignment_bp, params, start_row);

    private_assignment.padding();
    public_assignment.padding();

    zk::snark::plonk_assignment_table<BlueprintFieldType, arithmetization_params> assignments(private_assignment,
                                                                                              public_assignment);

    using params_type = zk::snark::redshift_params<BlueprintFieldType, arithmetization_params, hashes::keccak_1600<256>,
                                                   hashes::keccak_1600<256>, 1>;
    using policy_type = zk::snark::detail::redshift_policy<BlueprintFieldType, params_type>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType, typename params_type::merkle_hash_type,
                                                   typename params_type::transcript_hash_type, 2>;

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

    std::size_t permutation_size =
        zk::snark::plonk_table_description<BlueprintFieldType, arithmetization_params>::witness_columns +
        zk::snark::plonk_table_description<BlueprintFieldType, arithmetization_params>::public_input_columns +
        zk::snark::plonk_table_description<BlueprintFieldType, arithmetization_params>::constant_columns;

    typename policy_type::preprocessed_public_data_type public_preprocessed_data =
        zk::snark::redshift_public_preprocessor<BlueprintFieldType, params_type>::process(bp, public_assignment, desc,
                                                                                          fri_params, permutation_size);
    typename policy_type::preprocessed_private_data_type private_preprocessed_data =
        zk::snark::redshift_private_preprocessor<BlueprintFieldType, params_type>::process(bp, private_assignment,
                                                                                           desc);

    auto proof = zk::snark::redshift_prover<BlueprintFieldType, params_type>::process(
        public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

    //    if (!zk::snark::redshift_verifier<BlueprintFieldType, params>::process(public_preprocessed_data, proof, bp,
    //                                                                           fri_params)) {
    //        return -1;
    //    }
    using Endianness = nil::marshalling::option::big_endian;

#ifndef __EMSCRIPTEN__
//    if (vm.count("output")) {
//    }
#else

#endif
    std::string st = marshalling_to_blob<Endianness>(proof);
    return st.c_str();
}
}

int main(int argc, char *argv[]) {
    typedef hashes::sha2<256> hash_type;
    typedef algebra::curves::alt_bn128<254> system_curve_type;
    typedef algebra::curves::curve25519 signature_curve_type;
    typedef typename signature_curve_type::template g1_type<> group_type;
    typedef pubkey::eddsa<group_type, pubkey::eddsa_type::basic, void> signature_scheme_type;
    typedef typename pubkey::public_key<signature_scheme_type>::signature_type signature_type;

    std::string string, line;

#ifndef __EMSCRIPTEN__
    boost::program_options::options_description options("Solana 'Light-Client' State Proof Generator");
    // clang-format off
    options.add_options()("help,h", "Display help message")
    ("version,v", "Display version")
    ("output,o", boost::program_options::value< std::string >(),"Output file")
    ("input,i", boost::program_options::value< std::string >(), "Input file");
    // clang-format on

    boost::program_options::positional_options_description p;
    p.add("input", 1);

    boost::program_options::variables_map vm;
    boost::program_options::store(
        boost::program_options::command_line_parser(argc, argv).options(options).positional(p).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << options << std::endl;
        return 0;
    }

    if (vm["input"].as<std::string>() != "stdin" && vm.count("input")) {
        if (boost::filesystem::exists(vm["input"].as<std::string>())) {
            boost::filesystem::load_string_file(vm["input"].as<std::string>(), string);
        }
    } else {
        while (std::getline(std::cin, line)) {
            string += line + "\n";
        }
    }
#else
    while (std::getline(std::cin, line)) {
        string += line + "\n";
    }
#endif

    std::stringstream sstr(string, std::ios_base::in);

    boost::property_tree::ptree root;
    boost::property_tree::ptree const_root;
    // Load the json file in this ptree
    boost::property_tree::read_json(sstr, root);
    boost::property_tree::read_json(sstr, const_root);

    zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> proof = make_proof(root);
    zk::snark::verifier_index<nil::crypto3::algebra::curves::vesta> ver_index = make_verify_index(root, const_root);

#ifndef __EMSCRIPTEN__
    std::cout << proof_gen() << std::endl;
#endif
}