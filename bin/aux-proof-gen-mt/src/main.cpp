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

#define BOOST_APPLICATION_FEATURE_NS_SELECT_BOOST

#include <boost/application.hpp>

#undef B0

#include <boost/random.hpp>
#include <boost/random/random_device.hpp>
#include <boost/json/src.hpp>
#include <boost/optional.hpp>

#include <nil/actor/core/app_template.hh>
#include <nil/actor/core/reactor.hh>
#include <nil/actor/core/metrics_api.hh>
#include <nil/actor/core/print.hh>

#include <nil/actor/core/thread.hh>
#include <nil/actor/core/with_scheduling_group.hh>

#include <nil/aux-proof-gen-mt/aspects/actor.hpp>
#include <nil/aux-proof-gen-mt/aspects/args.hpp>
#include <nil/aux-proof-gen-mt/aspects/path.hpp>
#include <nil/aux-proof-gen-mt/aspects/configuration.hpp>
#include <nil/aux-proof-gen-mt/aspects/proof.hpp>
#include <nil/aux-proof-gen-mt/detail/configurable.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>

//#include <boost/filesystem.hpp>
//#include <boost/filesystem/string_file.hpp>
//#include <boost/program_options.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/alt_bn128.hpp>

#include <nil/actor/zk/blueprint/plonk.hpp>
#include <nil/actor/zk/assignment/plonk.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/verifier_base_field.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/verify_scalar.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include <nil/actor/zk/snark/systems/plonk/pickles/detail.hpp>
#include <nil/actor/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/actor/zk/snark/systems/plonk/pickles/verifier_index.hpp>
#include <nil/actor/zk/snark/systems/plonk/pickles/verifier.hpp>

#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/actor/zk/commitments/type_traits.hpp>
#include <nil/actor/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/actor/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/actor/zk/snark/systems/plonk/pickles/verifier_index.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/params.hpp>

#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>

#include "ec_index_terms.hpp"
#include "profiling_plonk_circuit.hpp"

#include <fstream>

using namespace nil;
using namespace nil::actor;

template<typename F, typename First, typename... Rest>
inline void insert_aspect(F f, First first, Rest... rest) {
    f(first);
    insert_aspect(f, rest...);
}

template<typename F>
inline void insert_aspect(F f) {
}

template<typename Application, typename... Aspects>
inline bool insert_aspects(boost::application::context &ctx, Application &app, Aspects... args) {
    insert_aspect([&](auto aspect) { ctx.insert<typename decltype(aspect)::element_type>(aspect); }, args...);

    boost::shared_ptr<nil::proof::aspects::path> path_aspect = boost::make_shared<nil::proof::aspects::path>();

    ctx.insert<nil::proof::aspects::path>(path_aspect);
    ctx.insert<nil::proof::aspects::configuration>(boost::make_shared<nil::proof::aspects::configuration>(path_aspect));
    ctx.insert<nil::proof::aspects::actor>(boost::make_shared<nil::proof::aspects::actor>(path_aspect));
    ctx.insert<nil::proof::aspects::proof>(boost::make_shared<nil::proof::aspects::proof>(path_aspect));

    return true;
}

template<typename Application>
inline bool configure_aspects(boost::application::context &ctx, Application &app) {
    typedef nil::proof::detail::configurable<nil::dbms::plugin::variables_map,
                                             nil::dbms::plugin::cli_options_description,
                                             nil::dbms::plugin::cfg_options_description>
        configurable_aspect_type;

    boost::strict_lock<boost::application::aspect_map> guard(ctx);
    boost::shared_ptr<nil::proof::aspects::args> args = ctx.find<nil::proof::aspects::args>(guard);
    boost::shared_ptr<nil::proof::aspects::configuration> cfg = ctx.find<nil::proof::aspects::configuration>(guard);

    for (boost::shared_ptr<void> itr : ctx) {
        boost::static_pointer_cast<configurable_aspect_type>(itr)->set_options(cfg->cli());
        boost::static_pointer_cast<configurable_aspect_type>(itr)->set_options(cfg->cfg());
    }

    try {
        boost::program_options::store(
            boost::program_options::parse_command_line(args->argc(), args->argv(), cfg->cli()), cfg->vm());
    } catch (const std::exception &e) {
        std::cout << e.what() << std::endl;
    }

    for (boost::shared_ptr<void> itr : ctx) {
        boost::static_pointer_cast<configurable_aspect_type>(itr)->initialize(cfg->vm());
    }

    return false;
}

using curve_type = nil::crypto3::algebra::curves::pallas;
using pallas_verifier_index_type = zk::snark::verifier_index<
    curve_type,
    nil::actor::zk::snark::arithmetic_sponge_params<curve_type::scalar_field_type::value_type>,
    nil::actor::zk::snark::arithmetic_sponge_params<curve_type::base_field_type::value_type>,
    nil::actor::zk::snark::kimchi_constant::COLUMNS,
    nil::actor::zk::snark::kimchi_constant::PERMUTES
    >;

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

    std::vector<std::shared_ptr<crypto3::math::evaluation_domain<FieldType>>> domain_set =
        crypto3::math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

    params.r = r;
    params.D = domain_set;
    params.max_degree = (1 << degree_log) - 1;

    params.step_list = generate_step_list(r, max_step);

    return params;
}

template<typename TIter>
void print_hex_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end, bool endl) {
    os << "0x" << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::dec;
    if (endl) {
        os << std::endl;
    }
}

template<typename Endianness, typename Proof>
void proof_print(const Proof &proof, std::string output_file) {
    //    using namespace nil::crypto3::marshalling;
    //
    //    using TTypeBase = nil::marshalling::field_type<Endianness>;
    //    using proof_marshalling_type = zk::snark::placeholder_proof<TTypeBase, Proof>;
    //    auto filled_placeholder_proof = crypto3::marshalling::types::fill_placeholder_proof<Endianness, Proof>(
    //        proof);
    //
    //    std::vector<std::uint8_t> cv;
    //    cv.resize(filled_placeholder_proof.length(), 0x00);
    //    auto write_iter = cv.begin();
    //    nil::marshalling::status_type status = filled_placeholder_proof.write(write_iter, cv.size());
    //    std::ofstream out;
    //    out.open(output_file);
    //    print_hex_byteblob(out, cv.cbegin(), cv.cend(), false);
}

// template<typename Endianness, typename RedshiftProof>
// std::string marshalling_to_blob(const RedshiftProof &proof) {
//     using namespace crypto3::marshalling;

//     auto filled_placeholder_proof = types::fill_placeholder_proof<RedshiftProof, Endianness>(proof);

//     std::vector<std::uint8_t> cv;
//     cv.resize(filled_placeholder_proof.length(), 0x00);
//     auto write_iter = cv.begin();
//     if (filled_placeholder_proof.write(write_iter, cv.size()) == nil::marshalling::status_type::success) {
//         std::stringstream st;
//         print_hex_byteblob(st, cv.cbegin(), cv.cend(), false);
//         return st.str();
//     } else {
//         return {};
//     }
// }

template<typename Iterator>
crypto3::multiprecision::cpp_int get_cppui256(Iterator it) {
    BOOST_ASSERT(it->second.template get_value<std::string>() != "");
    return crypto3::multiprecision::cpp_int(it->second.template get_value<std::string>());
}

template<typename CurveType>
void check_coord(crypto3::multiprecision::cpp_int &x, crypto3::multiprecision::cpp_int &y) {
    if (x == 0 && y == 1) { // circuit uses (0, 0) as point-at-infinity
        y = 0;
    }

    typename CurveType::base_field_type::value_type x_field = x;
    typename CurveType::base_field_type::value_type y_field = y;

    typename CurveType::base_field_type::value_type left_side = y_field * y_field;
    typename CurveType::base_field_type::value_type right_side = x_field * x_field * x_field;
    right_side += 5;
    if (left_side != right_side) {
        x = 0;
        y = 0;
    }
}

zk::snark::proof_type<curve_type> make_proof(boost::property_tree::ptree root) {
    typename zk::snark::proof_type<curve_type> proof;
    size_t i = 0;
    std::string base_path = "protocolStateProof.json.proof.";

    auto best_chain = *root.get_child("data.bestChain").begin();
    i = 0;
    for (auto &row : best_chain.second.get_child(base_path + "messages.w_comm")) {
        auto it = row.second.get_child("").begin()->second.get_child("").begin();
        auto x = get_cppui256(it);
        it++;
        auto y = get_cppui256(it);
        check_coord<curve_type>(x, y);
        proof.commitments.w_comm[i].unshifted.emplace_back(x, y);
        ++i;
    }
    auto it = best_chain.second.get_child(base_path + "messages.z_comm").begin()->second.get_child("").begin();
    auto x = get_cppui256(it);
    it++;
    auto y = get_cppui256(it);
    check_coord<curve_type>(x, y);
    proof.commitments.z_comm.unshifted.emplace_back(x, y);

    it = best_chain.second.get_child(base_path + "messages.t_comm").begin()->second.get_child("").begin();
    x = get_cppui256(it);
    it++;
    y = get_cppui256(it);
    check_coord<curve_type>(x, y);
    proof.commitments.t_comm.unshifted.emplace_back(x, y);
    //    proof.commitments.lookup;    // TODO: where it is?

    i = 0;
    for (auto &row : best_chain.second.get_child(base_path + "openings.proof.lr")) {
        auto it0 = row.second.begin()->second.get_child("").begin();
        auto x0 = get_cppui256(it0);
        it0++;
        auto y0 = get_cppui256(it0);
        if (x0 == 0 && y0 == 1) { // circuit uses (0, 0) as point-at-infinity
            y0 = 0;
        }
        auto it1 = row.second.begin();
        it1++;
        it1 = it1->second.begin();
        auto x1 = get_cppui256(it1);
        it1++;
        auto y1 = get_cppui256(it1);
        if (x1 == 0 && y1 == 1) { // circuit uses (0, 0) as point-at-infinity
            y1 = 0;
        }
        proof.proof.lr.push_back({{x0, y0}, {x1, y1}});
        ++i;
    }
    it = best_chain.second.get_child(base_path + "openings.proof.delta").begin();
    x = get_cppui256(it);
    it++;
    y = get_cppui256(it);
    check_coord<curve_type>(x, y);
    proof.proof.delta = {x, y};
    it = best_chain.second.get_child(base_path + "openings.proof.challenge_polynomial_commitment").begin();
    x = get_cppui256(it);
    it++;
    y = get_cppui256(it);
    check_coord<curve_type>(x, y);
    proof.proof.sg = {x, y};

    proof.proof.z1 = crypto3::multiprecision::cpp_int(best_chain.second.get<std::string>(base_path + "openings.proof.z_1"));
    proof.proof.z2 = crypto3::multiprecision::cpp_int(best_chain.second.get<std::string>(base_path + "openings.proof.z_2"));

    auto evals_it = best_chain.second.get_child(base_path + "openings.evals");
    i = 0;
    std::size_t ev_i = 0;
    for (auto &row : evals_it.get_child("w")) {
        ev_i = 0;
        for (auto &eval_at_point : row.second) {
            for (auto &cell : eval_at_point.second) {
                proof.evals[ev_i].w[i].push_back(get_cppui256(&cell));
            }
            ev_i++;
        }
        i++;
    }

    ev_i = 0;
    for(auto &z_it : evals_it.get_child("z")){
        for (auto &cell : z_it.second) {
            proof.evals[ev_i].z.push_back(get_cppui256(&cell));
        }
        ev_i++;
    }

    i = 0;
    for (auto &row : evals_it.get_child("s")) {
        ev_i = 0;
        for (auto &eval_at_point : row.second) {
            for (auto &cell : eval_at_point.second) {
                proof.evals[ev_i].s[i].push_back(get_cppui256(&cell));
            }
            ev_i++;
        }
        i++;
    }

    ev_i = 0;
    for(auto &gs_it : evals_it.get_child("generic_selector") ){
        for (auto &cell : gs_it.second) {
            proof.evals[ev_i].generic_selector.push_back(get_cppui256(&cell));
        }
        ev_i++;
    }

    ev_i = 0;
    for(auto &ps_it : evals_it.get_child("poseidon_selector") ){
        for (auto &cell : ps_it.second) {
            proof.evals[ev_i].poseidon_selector.push_back(get_cppui256(&cell));
        }
        ev_i++;
    }

    proof.ft_eval1 = crypto3::multiprecision::cpp_int(best_chain.second.get<std::string>(base_path + "openings.ft_eval1"));
    //            // public
    //            std::vector<typename CurveType::scalar_field_type::value_type> public_p; // TODO: where it is?
    //
    //            // Previous challenges
    //            std::vector<
    //                std::tuple<std::vector<typename CurveType::scalar_field_type::value_type>, commitment_scheme>>
    //                prev_challenges; // TODO: where it is?
    return proof;
}

pallas_verifier_index_type make_verify_index(boost::property_tree::ptree root, boost::property_tree::ptree const_root) {
    using curve_type = typename nil::crypto3::algebra::curves::pallas;

    pallas_verifier_index_type ver_index;
    size_t i = 0;

    // TODO Is it right? Is it a good way to set domain generator?
    // We need to assert, need to check that the input is indeed the root of unity

    auto d_gen = crypto3::multiprecision::cpp_int(const_root.get<std::string>("verify_index.domain.group_gen"));
    auto d_size = const_root.get<std::size_t>("verify_index.domain.log_size_of_group");
    // std::cout << d_gen << " " << d_size << std::endl;
    ver_index.domain = nil::crypto3::math::basic_radix2_domain<typename curve_type::scalar_field_type>(d_size+1);
    // std::cout << ver_index.domain.omega.data << std::endl;
    ver_index.domain.omega = d_gen;


    ver_index.max_poly_size = root.get<std::size_t>("data.blockchainVerificationKey.index.max_poly_size");
    ver_index.max_quot_size = root.get<std::size_t>("data.blockchainVerificationKey.index.max_quot_size");
    //    ver_index.srs = root.get<std::string>("data.blockchainVerificationKey.index.srs");    // TODO: null
    i = 0;
    for (auto &row : root.get_child("data.blockchainVerificationKey.commitments.sigma_comm")) {
        auto it = row.second.begin();
        auto x = get_cppui256(it);
        it++;
        auto y = get_cppui256(it);
        check_coord<curve_type>(x, y);
        ver_index.sigma_comm[i].unshifted.emplace_back(x, y);
        ++i;
    }

    i = 0;
    for (auto &row : root.get_child("data.blockchainVerificationKey.commitments.coefficients_comm")) {
        auto it = row.second.begin();
        auto x = get_cppui256(it);
        it++;
        auto y = get_cppui256(it);
        check_coord<curve_type>(x, y);
        ver_index.coefficients_comm[i].unshifted.emplace_back(x, y);
        ++i;
    }
    auto it = root.get_child("data.blockchainVerificationKey.commitments.generic_comm").begin();
    auto x = get_cppui256(it);
    it++;
    auto y = get_cppui256(it);
    check_coord<curve_type>(x, y);
    ver_index.generic_comm.unshifted.emplace_back(x, y);

    it = root.get_child("data.blockchainVerificationKey.commitments.psm_comm").begin();
    x = get_cppui256(it);
    it++;
    y = get_cppui256(it);
    check_coord<curve_type>(x, y);
    ver_index.psm_comm.unshifted.emplace_back(x, y);
    it = root.get_child("data.blockchainVerificationKey.commitments.complete_add_comm").begin();
    x = get_cppui256(it);
    it++;
    y = get_cppui256(it);
    check_coord<curve_type>(x, y);
    ver_index.complete_add_comm.unshifted.emplace_back(x, y);
    it = root.get_child("data.blockchainVerificationKey.commitments.mul_comm").begin();
    x = get_cppui256(it);
    it++;
    y = get_cppui256(it);
    check_coord<curve_type>(x, y);
    ver_index.mul_comm.unshifted.emplace_back(x, y);
    it = root.get_child("data.blockchainVerificationKey.commitments.emul_comm").begin();
    x = get_cppui256(it);
    it++;
    y = get_cppui256(it);
    check_coord<curve_type>(x, y);
    ver_index.emul_comm.unshifted.emplace_back(x, y);
    it = root.get_child("data.blockchainVerificationKey.commitments.endomul_scalar_comm").begin();
    x = get_cppui256(it);
    it++;
    y = get_cppui256(it);
    check_coord<curve_type>(x, y);
    ver_index.endomul_scalar_comm.unshifted.emplace_back(x, y);

    // TODO: null in example
    //    i = 0;
    //    for (auto &row : root.get_child("data.blockchainVerificationKey.commitments.chacha_comm")) {
    //        auto it = row.second.begin();
    //        ver_index.chacha_comm[i].unshifted.emplace_back(get_cppui256(it++), get_cppui256(it));
    //        ++i;
    //    }
    //i = 0;
    // No member shifts
    //for (auto &row : root.get_child("data.blockchainVerificationKey.index.shifts")) {
    //    ver_index.shifts[i] = multiprecision::cpp_int(row.second.get_value<std::string>());
    //    ++i;
    //}

    // Polynomial in coefficients form
    // Const
    ver_index.zkpm = {0x2C46205451F6C3BBEA4BABACBEE609ECF1039A903C42BFF639EDC5BA33356332_cppui256,
                      0x1764D9CB4C64EBA9A150920807637D458919CB6948821F4D15EB1994EADF9CE3_cppui256,
                      0x0140117C8BBC4CE4644A58F7007148577782213065BB9699BF5C391FBE1B3E6D_cppui256,
                      0x0000000000000000000000000000000000000000000000000000000000000001_cppui256};
    ver_index.w = crypto3::multiprecision::cpp_int(const_root.get<std::string>("verify_index.w"));
    ver_index.endo = crypto3::multiprecision::cpp_int(const_root.get<std::string>("verify_index.endo"));

    //ver_index.lookup_index = root.get_child("data.blockchainVerificationKey.index.lookup_index"); // TODO: null
    //ver_index.linearization;       // TODO: where it is?
    ver_index.powers_of_alpha.next_power = 24;

    i = 0;
    ver_index.fr_sponge_params.round_constants.resize(const_root.get_child("verify_index.fr_sponge_params.round_constants").size());
    for (auto &row : const_root.get_child("verify_index.fr_sponge_params.round_constants")) {
        size_t j = 0;
        for (auto cell : row.second){
            ver_index.fr_sponge_params.round_constants[i].push_back(get_cppui256(&cell));
            j++;
        }
        i++;
    }

    i = 0;
    for (auto &row : const_root.get_child("verify_index.fr_sponge_params.mds")) {
        size_t j = 0;
        for (auto cell : row.second){
            ver_index.fr_sponge_params.mds[i][j] = get_cppui256(&cell);
            j++;
        }
        i++;
    }

    i = 0;
    ver_index.fq_sponge_params.round_constants.resize(const_root.get_child("verify_index.fq_sponge_params.round_constants").size());
    for (auto &row : const_root.get_child("verify_index.fq_sponge_params.round_constants")) {
        size_t j = 0;
        for (auto cell : row.second){
            ver_index.fq_sponge_params.round_constants[i].push_back(get_cppui256(&cell));
            j++;
        }
        i++;
    }

    i = 0;
    for (auto &row : const_root.get_child("verify_index.fq_sponge_params.mds")) {
        size_t j = 0;
        for (auto cell : row.second){
            ver_index.fr_sponge_params.mds[i][j] = get_cppui256(&cell);
            j++;
        }
        i++;
    }

    // TODO: Add assertions about right size of
    //      fr_sponge_params.mds,
    //      fr_sponge_params.round_constants,

    return ver_index;
}

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType, std::size_t EvalRounds>
void prepare_proof_scalar(zk::snark::proof_type<nil::crypto3::algebra::curves::pallas> &original_proof,
                          zk::components::kimchi_proof_scalar<BlueprintFieldType, KimchiParamsType, EvalRounds> &circuit_proof,
                          std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    // eval_proofs
    for (std::size_t point_idx = 0; point_idx < 2; point_idx++) {
        // w
        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
            public_input.push_back(original_proof.evals[point_idx].w[i][0]);
            circuit_proof.proof_evals[point_idx].w[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // z
        public_input.push_back(original_proof.evals[point_idx].z[0]);
        circuit_proof.proof_evals[point_idx].z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        // s
        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
            public_input.push_back(original_proof.evals[point_idx].s[i][0]);
            circuit_proof.proof_evals[point_idx].s[i] =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
        // lookup
        if (KimchiParamsType::use_lookup) {
            // TODO
        }
        // generic_selector
        public_input.push_back(original_proof.evals[point_idx].generic_selector[0]);
        circuit_proof.proof_evals[point_idx].generic_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        // poseidon_selector
        public_input.push_back(original_proof.evals[point_idx].poseidon_selector[0]);
        circuit_proof.proof_evals[point_idx].poseidon_selector =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    typename BlueprintFieldType::value_type scalar_value = 2;

    for (std::size_t i = 0; i < KimchiParamsType::public_input_size; i++) {
        public_input.push_back(scalar_value);
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

    // opening proof
    public_input.push_back(scalar_value);
    circuit_proof.opening.z1 = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(scalar_value);
    circuit_proof.opening.z2 = var(0, public_input.size() - 1, false, var::column_type::public_input);
}

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType, std::size_t EvalRounds>
void prepare_proof_base(zk::snark::proof_type<nil::crypto3::algebra::curves::pallas> &original_proof,
                        zk::components::kimchi_proof_base<BlueprintFieldType, KimchiParamsType> &circuit_proof,
                        std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    using kimchi_constants = zk::components::kimchi_inner_constants<KimchiParamsType>;

    // COMMITMENTS
    for (std::size_t i = 0; i < original_proof.commitments.w_comm.size(); i++) {
        assert(circuit_proof.comm.witness.size() > i);
        for (std::size_t j = 0; j < original_proof.commitments.w_comm[i].unshifted.size(); j++) {
            assert(circuit_proof.comm.witness[i].parts.size() > j);
            public_input.push_back(original_proof.commitments.w_comm[i].unshifted[j].X);
            circuit_proof.comm.witness[i].parts[j].X =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
            public_input.push_back(original_proof.commitments.w_comm[i].unshifted[j].Y);
            circuit_proof.comm.witness[i].parts[j].Y =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }

    for (std::size_t j = 0; j < original_proof.commitments.z_comm.unshifted.size(); j++) {
        assert(circuit_proof.comm.z.parts.size() > j);
        public_input.push_back(original_proof.commitments.z_comm.unshifted[j].X);
        circuit_proof.comm.z.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(original_proof.commitments.z_comm.unshifted[j].Y);
        circuit_proof.comm.z.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t j = 0; j < original_proof.commitments.t_comm.unshifted.size(); j++) {
        assert(circuit_proof.comm.t.parts.size() > j);
        public_input.push_back(original_proof.commitments.t_comm.unshifted[j].X);
        circuit_proof.comm.t.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(original_proof.commitments.t_comm.unshifted[j].Y);
        circuit_proof.comm.t.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t i = 0; i < original_proof.commitments.lookup.sorted.size(); i++) {
        assert(circuit_proof.comm.lookup_sorted.size() > i);
        for (std::size_t j = 0; j < original_proof.commitments.lookup.sorted[i].unshifted.size(); j++) {
            assert(circuit_proof.comm.lookup_sorted[i].parts.size() > j);
            public_input.push_back(original_proof.commitments.lookup.sorted[i].unshifted[j].X);
            circuit_proof.comm.lookup_sorted[i].parts[j].X =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
            public_input.push_back(original_proof.commitments.lookup.sorted[i].unshifted[j].Y);
            circuit_proof.comm.lookup_sorted[i].parts[j].Y =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }

    for (std::size_t j = 0; j < original_proof.commitments.lookup.aggreg.unshifted.size(); j++) {
        assert(circuit_proof.comm.lookup_agg.parts.size() > j);
        public_input.push_back(original_proof.commitments.lookup.aggreg.unshifted[j].X);
        circuit_proof.comm.lookup_agg.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(original_proof.commitments.lookup.aggreg.unshifted[j].Y);
        circuit_proof.comm.lookup_agg.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t j = 0; j < original_proof.commitments.lookup.runtime.unshifted.size(); j++) {
        assert(circuit_proof.comm.lookup_runtime.parts.size() > j);
        public_input.push_back(original_proof.commitments.lookup.runtime.unshifted[j].X);
        circuit_proof.comm.lookup_runtime.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(original_proof.commitments.lookup.runtime.unshifted[j].Y);
        circuit_proof.comm.lookup_runtime.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t j = 0; j < circuit_proof.comm.table.parts.size(); j++) {
        assert(circuit_proof.comm.table.parts.size() > j);
        typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type point =
            original_proof.commitments.z_comm.unshifted[0];
        public_input.push_back(point.X);
        circuit_proof.comm.table.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(point.Y);
        circuit_proof.comm.table.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    // OPENING PROOF
    std::size_t min_lr_size = std::min(original_proof.proof.lr.size(), circuit_proof.o.L.size());
    for (std::size_t i = 0; i < min_lr_size; i++) {
        public_input.push_back(std::get<0>(original_proof.proof.lr[i]).X);
        circuit_proof.o.L[i].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(std::get<0>(original_proof.proof.lr[i]).Y);
        circuit_proof.o.L[i].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);

        public_input.push_back(std::get<1>(original_proof.proof.lr[i]).X);
        circuit_proof.o.R[i].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(std::get<1>(original_proof.proof.lr[i]).Y);
        circuit_proof.o.R[i].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    public_input.push_back(original_proof.proof.delta.X);
    circuit_proof.o.delta.X =
        var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(original_proof.proof.delta.Y);
    circuit_proof.o.delta.Y =
        var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(original_proof.proof.sg.X);
    circuit_proof.o.G.X =
        var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(original_proof.proof.sg.Y);
    circuit_proof.o.G.Y =
        var(0, public_input.size() - 1, false, var::column_type::public_input);

    for (std::size_t i = 0; i < kimchi_constants::f_comm_msm_size; i++) {
        typename BlueprintFieldType::value_type x  = 3;
        public_input.push_back(x);
        circuit_proof.scalars[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }
}

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType>
void prepare_index_base(pallas_verifier_index_type &original_index,
                        zk::components::kimchi_verifier_index_base<CurveType, KimchiParamsType> &circuit_index,
                        std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    // COMMITMENTS
    for (std::size_t i = 0; i < original_index.sigma_comm.size(); i++) {
        assert(circuit_index.comm.sigma.size() > i);
        for (std::size_t j = 0; j < original_index.sigma_comm[i].unshifted.size(); j++) {
            assert(circuit_index.comm.sigma[i].parts.size() > j);
            public_input.push_back(original_index.sigma_comm[i].unshifted[j].X);
            circuit_index.comm.sigma[i].parts[j].X =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
            public_input.push_back(original_index.sigma_comm[i].unshifted[j].Y);
            circuit_index.comm.sigma[i].parts[j].Y =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }

    for (std::size_t i = 0; i < original_index.coefficients_comm.size(); i++) {
        assert(circuit_index.comm.coefficient.size() > i);
        for (std::size_t j = 0; j < original_index.coefficients_comm[i].unshifted.size(); j++) {
            assert(circuit_index.comm.coefficient[i].parts.size() > j);
            public_input.push_back(original_index.coefficients_comm[i].unshifted[j].X);
            circuit_index.comm.coefficient[i].parts[j].X =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
            public_input.push_back(original_index.coefficients_comm[i].unshifted[j].Y);
            circuit_index.comm.coefficient[i].parts[j].Y =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }

    for (std::size_t j = 0; j < original_index.generic_comm.unshifted.size(); j++) {
        assert(circuit_index.comm.generic.parts.size() > j);
        public_input.push_back(original_index.generic_comm.unshifted[j].X);
        circuit_index.comm.generic.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(original_index.generic_comm.unshifted[j].Y);
        circuit_index.comm.generic.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t j = 0; j < original_index.psm_comm.unshifted.size(); j++) {
        assert(circuit_index.comm.psm.parts.size() > j);
        public_input.push_back(original_index.psm_comm.unshifted[j].X);
        circuit_index.comm.psm.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(original_index.psm_comm.unshifted[j].Y);
        circuit_index.comm.psm.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t j = 0; j < original_index.complete_add_comm.unshifted.size(); j++) {
        assert(circuit_index.comm.complete_add.parts.size() > j);
        public_input.push_back(original_index.complete_add_comm.unshifted[j].X);
        circuit_index.comm.complete_add.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(original_index.complete_add_comm.unshifted[j].Y);
        circuit_index.comm.complete_add.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t j = 0; j < original_index.mul_comm.unshifted.size(); j++) {
        assert(circuit_index.comm.var_base_mul.parts.size() > j);
        public_input.push_back(original_index.mul_comm.unshifted[j].X);
        circuit_index.comm.var_base_mul.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(original_index.mul_comm.unshifted[j].Y);
        circuit_index.comm.var_base_mul.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t j = 0; j < original_index.emul_comm.unshifted.size(); j++) {
        assert(circuit_index.comm.endo_mul.parts.size() > j);
        public_input.push_back(original_index.emul_comm.unshifted[j].X);
        circuit_index.comm.endo_mul.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(original_index.emul_comm.unshifted[j].Y);
        circuit_index.comm.endo_mul.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t j = 0; j < original_index.endomul_scalar_comm.unshifted.size(); j++) {
        assert(circuit_index.comm.endo_mul_scalar.parts.size() > j);
        public_input.push_back(original_index.endomul_scalar_comm.unshifted[j].X);
        circuit_index.comm.endo_mul_scalar.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(original_index.endomul_scalar_comm.unshifted[j].Y);
        circuit_index.comm.endo_mul_scalar.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t i = 0; i < original_index.chacha_comm.size(); i++) {
        assert(circuit_index.comm.chacha.size() > i);
        for (std::size_t j = 0; j < original_index.chacha_comm[i].unshifted.size(); j++) {
            assert(circuit_index.comm.chacha[i].parts.size() > j);
            public_input.push_back(original_index.chacha_comm[i].unshifted[j].X);
            circuit_index.comm.chacha[i].parts[j].X =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
            public_input.push_back(original_index.chacha_comm[i].unshifted[j].Y);
            circuit_index.comm.chacha[i].parts[j].Y =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }

    for (std::size_t i = 0; i < original_index.range_check_comm.size(); i++) {
        assert(circuit_index.comm.range_check.size() > i);
        for (std::size_t j = 0; j < original_index.range_check_comm[i].unshifted.size(); j++) {
            assert(circuit_index.comm.range_check[i].parts.size() > j);
            public_input.push_back(original_index.range_check_comm[i].unshifted[j].X);
            circuit_index.comm.range_check[i].parts[j].X =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
            public_input.push_back(original_index.range_check_comm[i].unshifted[j].Y);
            circuit_index.comm.range_check[i].parts[j].Y =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }

    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type point =
        original_index.sigma_comm[0].unshifted[0];

    for (std::size_t i = 0; i < circuit_index.comm.selectors.size(); i++) {
        for (std::size_t j = 0; j < circuit_index.comm.selectors[i].parts.size(); j++) {
            public_input.push_back(point.X);
            circuit_index.comm.selectors[i].parts[j].X =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
            public_input.push_back(point.Y);
            circuit_index.comm.selectors[i].parts[j].Y =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }

    for (std::size_t i = 0; i < circuit_index.comm.lookup_selectors.size(); i++) {
        for (std::size_t j = 0; j < circuit_index.comm.lookup_selectors[i].parts.size(); j++) {
            public_input.push_back(point.X);
            circuit_index.comm.lookup_selectors[i].parts[j].X =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
            public_input.push_back(point.Y);
            circuit_index.comm.lookup_selectors[i].parts[j].Y =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }

    for (std::size_t i = 0; i < circuit_index.comm.lookup_table.size(); i++) {
        for (std::size_t j = 0; j < circuit_index.comm.lookup_table[i].parts.size(); j++) {
            public_input.push_back(point.X);
            circuit_index.comm.lookup_table[i].parts[j].X =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
            public_input.push_back(point.Y);
            circuit_index.comm.lookup_table[i].parts[j].Y =
                var(0, public_input.size() - 1, false, var::column_type::public_input);
        }
    }

    for (std::size_t j = 0; j < circuit_index.comm.runtime_tables_selector.parts.size(); j++) {
        public_input.push_back(point.X);
        circuit_index.comm.runtime_tables_selector.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(point.Y);
        circuit_index.comm.runtime_tables_selector.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    // POINTS
    public_input.push_back(point.X); // todo srs.h is not used during parsing
    circuit_index.H.X = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(point.Y);
    circuit_index.H.Y = var(0, public_input.size() - 1, false, var::column_type::public_input);

    for (std::size_t i = 0; i < KimchiParamsType::commitment_params_type::srs_len; i++) {
        public_input.push_back(point.X);
        circuit_index.G[i].X = var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(point.Y);
        circuit_index.G[i].Y = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t i = 0; i < KimchiParamsType::public_input_size; i++) {
        public_input.push_back(point.X); // todo srs.lagrange_bases is not used during parsing
        circuit_index.lagrange_bases[i].X = var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(point.Y);
        circuit_index.lagrange_bases[i].Y = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }
}

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType>
void prepare_index_scalar(pallas_verifier_index_type &original_index,
                          zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> &circuit_index,
                          std::vector<typename BlueprintFieldType::value_type> &public_input) {
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    circuit_index.domain_size = original_index.domain.m;

    for (std::size_t i = 0; i < original_index.shift.size(); i++) {
        public_input.push_back(original_index.shift[i]);
        circuit_index.shift[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    public_input.push_back(original_index.w);
    circuit_index.omega = var(0, public_input.size() - 1, false, var::column_type::public_input);
}

template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
         std::size_t Lambda, typename FunctorResultCheck, typename PublicInput,
         typename std::enable_if<
             std::is_same<typename BlueprintFieldType::value_type,
                          typename std::iterator_traits<typename PublicInput::iterator>::value_type>::value,
             bool>::type = true>
auto prepare_component(typename ComponentType::params_type params, const PublicInput &public_input, const std::size_t max_step,
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

    result_check(assignment_bp, component_result);

    assignment_bp.padding();
    std::cout << "Usable rows: " << desc.usable_rows_amount << std::endl;
    std::cout << "Padded rows: " << desc.rows_amount << std::endl;

    zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(private_assignment,
                                                                                             public_assignment);

    using placeholder_params =
        zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;
    using types = zk::snark::detail::placeholder_policy<BlueprintFieldType, placeholder_params>;

    using fri_type =
        typename zk::commitments::fri<BlueprintFieldType, typename placeholder_params::merkle_hash_type,
                                      typename placeholder_params::transcript_hash_type, 2, 1>;

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log, max_step);

    std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

    typename zk::snark::placeholder_public_preprocessor<
        BlueprintFieldType, placeholder_params>::preprocessed_data_type public_preprocessed_data =
        zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params>::process(
            bp, public_assignment, desc, fri_params, permutation_size).get();
    typename zk::snark::placeholder_private_preprocessor<
        BlueprintFieldType, placeholder_params>::preprocessed_data_type private_preprocessed_data =
        zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params>::process(
            bp, private_assignment, desc, fri_params).get();

    return std::make_tuple(desc, bp, fri_params, assignments, public_preprocessed_data,
                           private_preprocessed_data);
}

//#ifdef __EMSCRIPTEN__
//extern "C" {
//template<std::size_t EvalRounds>
//const char *generate_proof_base(zk::snark::pickles_proof<nil::crypto3::algebra::curves::pallas> &pickles_proof,
//                                pallas_verifier_index_type &pickles_index, const std::size_t fri_max_step, std::string output_path) {
//#else
//template<std::size_t EvalRounds>
//std::string generate_proof_base(zk::snark::proof_type<nil::crypto3::algebra::curves::pallas> &pickles_proof,
//                                pallas_verifier_index_type &pickles_index, const std::size_t fri_max_step, std::string output_path) {
//#endif
//    using curve_type = crypto3::algebra::curves::pallas;
//    using BlueprintFieldType = typename curve_type::base_field_type;
//    constexpr std::size_t WitnessColumns = 15;
//    constexpr std::size_t PublicInputColumns = 1;
//    constexpr std::size_t ConstantColumns = 1;
//    constexpr std::size_t SelectorColumns = 30;
//    using ArithmetizationParams =
//        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
//    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//    constexpr std::size_t Lambda = 1;
//
//    using var = zk::snark::plonk_variable<BlueprintFieldType>;
//
//    constexpr static std::size_t public_input_size = 0;
//    constexpr static std::size_t max_poly_size = 1 << EvalRounds; // 32768 in json
//    constexpr static std::size_t srs_len = max_poly_size;
//    constexpr static std::size_t eval_rounds = EvalRounds; // 15 in json
//
//    constexpr static std::size_t witness_columns = 15;
//    constexpr static std::size_t perm_size = 7;
//    constexpr static std::size_t lookup_table_size = 0;
//    constexpr static bool use_lookup = false;
//
//    constexpr static std::size_t batch_size = 1;
//
//    constexpr static const std::size_t prev_chal_size = 0;
//
//    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
//    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
//    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
//                                                                           witness_columns, perm_size>;
//    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
//                                                             public_input_size, prev_chal_size>;
//
//    using component_type = zk::components::base_field<ArithmetizationType,
//                                                      curve_type,
//                                                      kimchi_params,
//                                                      commitment_params,
//                                                      batch_size,
//                                                      0,
//                                                      1,
//                                                      2,
//                                                      3,
//                                                      4,
//                                                      5,
//                                                      6,
//                                                      7,
//                                                      8,
//                                                      9,
//                                                      10,
//                                                      11,
//                                                      12,
//                                                      13,
//                                                      14>;
//
//    using fq_output_type =
//        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output;
//
//    using fr_data_type = typename zk::components::binding<ArithmetizationType, BlueprintFieldType,
//                                                          kimchi_params>::template fr_data<var, batch_size>;
//
//    using fq_data_type =
//        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::template fq_data<var>;
//
//    std::vector<typename BlueprintFieldType::value_type> public_input = {};
//
//    std::vector<zk::components::kimchi_proof_base<BlueprintFieldType, kimchi_params>> proofs;
//    proofs.resize(batch_size);
//
//    for (std::size_t batch_id = 0; batch_id < batch_size; batch_id++) {
//        zk::components::kimchi_proof_base<BlueprintFieldType, kimchi_params> proof;
//
//        prepare_proof_base<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(pickles_proof, proof, public_input);
//
//        proofs[batch_id] = proof;
//    }
//
//    zk::components::kimchi_verifier_index_base<curve_type, kimchi_params> verifier_index;
//    prepare_index_base<curve_type, BlueprintFieldType, kimchi_params>(pickles_index, verifier_index, public_input);
//
//    fr_data_type fr_data_public;
//    fq_data_type fq_data_public;
//
//    public_input.push_back(3);
//    for (std::size_t i = 0; i < fr_data_public.scalars.size(); i++) {
//        var s(0, public_input.size() - 1, false, var::column_type::public_input);
//        fr_data_public.scalars[i] = s;
//    }
//
//    typename component_type::params_type params = {proofs, verifier_index, fr_data_public, fq_data_public};
//
//    auto result_check = [](AssignmentType &assignment, typename component_type::result_type &real_res) {};
//
//    //using Endianness = nil::marshalling::option::big_endian;
//
//    using placeholder_params =
//        zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, hash_type, hash_type, Lambda>;
//
//    auto [desc, bp, fri_params, assignments, public_preprocessed_data, private_preprocessed_data] =
//        prepare_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
//            params, public_input, fri_max_step, result_check);
//
//    auto proof = zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params>::process(
//        public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);
//
//    bool verifier_res = zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params>::process(
//        public_preprocessed_data, proof, bp, fri_params);
//
//    if (verifier_res) {
//        std::cout << "Verification passed" << std::endl;
//    } else {
//        std::cout << "Verification failed" << std::endl;
//    }
//    //
//    //    std::string output_path_full = output_path + "_base";
//    //    proof_print<nil::marshalling::option::big_endian>(
//    //        proof, output_path_full);
//
//    //std::string st = marshalling_to_blob<Endianness>(proof);
//    std::string st;
//#ifdef __EMSCRIPTEN__
//    char *writable = new char[st.size() + 1];
//    std::copy(st.begin(), st.end(), writable);
//    return writable;
//#else
//    return st;
//#endif
//}

#ifdef __EMSCRIPTEN__
extern "C" {
template<std::size_t EvalRounds>
const char *generate_proof_scalar(zk::snark::pickles_proof<nil::crypto3::algebra::curves::pallas> &pickles_proof,
                                  pallas_verifier_index_type &pickles_index, const std::size_t fri_max_step, std::string output_path) {
#else
template<std::size_t EvalRounds>
std::string generate_proof_scalar(zk::snark::proof_type<nil::crypto3::algebra::curves::pallas> &pickles_proof,
                                  pallas_verifier_index_type &pickles_index, const std::size_t fri_max_step, std::string output_path) {
#endif
    using curve_type = crypto3::algebra::curves::pallas;
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
constexpr static std::size_t max_poly_size = 1 << EvalRounds; // 32768 in json
constexpr static std::size_t srs_len = max_poly_size;
constexpr static std::size_t eval_rounds = EvalRounds; // 15 in json

constexpr static std::size_t witness_columns = 15;
constexpr static std::size_t perm_size = 7;
constexpr static std::size_t lookup_table_size = 0;

constexpr static std::size_t batch_size = 1;

constexpr static const std::size_t prev_chal_size = 0;

using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
                                                                       witness_columns, perm_size>;
using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                         public_input_size, prev_chal_size>;

using component_type = zk::components::verify_scalar<ArithmetizationType, curve_type, kimchi_params, commitment_params, batch_size, 0,
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

    prepare_proof_scalar<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(pickles_proof, proof, public_input);

    proofs[batch_id] = proof;
}

zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
prepare_index_scalar<curve_type, BlueprintFieldType, kimchi_params>(pickles_index, verifier_index, public_input);
verifier_index.domain_size = max_poly_size;

using fq_output_type =
    typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output;

fr_data_type fr_data_public;
fq_data_type fq_data_public;
std::array<fq_output_type, batch_size> fq_outputs;

typename component_type::params_type params = {fr_data_public, fq_data_public, verifier_index, proofs, fq_outputs};

auto result_check = [](AssignmentType &assignment, typename component_type::result_type &real_res) {};

//using Endianness = nil::marshalling::option::big_endian;

using placeholder_params =
    zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, hash_type, hash_type, Lambda>;

auto [desc, bp, fri_params, assignments, public_preprocessed_data, private_preprocessed_data] =
    prepare_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, fri_max_step, result_check);

auto proof = zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params>::process(
    public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

bool verifier_res = zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params>::process(
    public_preprocessed_data, proof, bp, fri_params);

if (verifier_res) {
    std::cout << "Verification passed" << std::endl;
} else {
    std::cout << "Verification failed" << std::endl;
}

std::string output_path_full = output_path + "_scalar";
proof_print<nil::marshalling::option::big_endian>(proof, output_path_full);

std::string st;
#ifdef __EMSCRIPTEN__
char *writable = new char[st.size() + 1];
std::copy(st.begin(), st.end(), writable);
return writable;
#else
    return st;
#endif
}

zk::snark::proof_type<nil::crypto3::algebra::curves::pallas> parse_proof(const char *kimchi) {
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

    pallas_verifier_index_type ver_index = make_verify_index(root, const_root);
    return 0;
}

#ifdef __EMSCRIPTEN__
}
#endif

nil::actor::future<> proof_new() {
    return nil::actor::async([&] {
        std::string output = "/root/mina-updated/mina-state-proof/bin/aux-proof-gen/src/data/output";
        boost::property_tree::ptree root;
        boost::property_tree::ptree const_root;
        boost::property_tree::read_json("/root/kimchi.json", root);
        boost::property_tree::read_json("/root/kimchi_const.json", const_root);
        zk::snark::proof_type<nil::crypto3::algebra::curves::pallas> proof = make_proof(root);
        pallas_verifier_index_type ver_index = make_verify_index(root, const_root);
        constexpr const std::size_t eval_rounds_base = 10;
        constexpr const std::size_t eval_rounds_scalar = 15;
        std::size_t fri_max_step = 1;
//        std::cout << std::string(generate_proof_base<eval_rounds_base>(proof, ver_index, fri_max_step, output)) << std::endl;
        std::cout << std::string(generate_proof_scalar<eval_rounds_scalar>(proof, ver_index, fri_max_step, output)) << std::endl;
    });
}

struct prover {
    typedef nil::crypto3::hashes::sha2<256> hash_type;
    typedef nil::crypto3::algebra::curves::ed25519 signature_curve_type;
    typedef typename signature_curve_type::template g1_type<> group_type;
    typedef nil::crypto3::pubkey::eddsa<group_type, nil::crypto3::pubkey::eddsa_type::basic, void> signature_scheme_type;
    typedef typename nil::crypto3::pubkey::public_key<signature_scheme_type>::signature_type signature_type;

    prover(boost::application::context &context) : context_(context) {
    }

    int operator()() {
        BOOST_APPLICATION_FEATURE_SELECT
            (void)nil::actor::engine().when_started().then(
                    []() {return proof_new();}).then_wrapped([](auto &&f) {
                    try {
                        engine().exit(0);
                    } catch (std::exception &ex) {
                        engine().exit(1);
                    }
                });
        auto exit_code = nil::actor::engine().run();
        std::cout << exit_code << std::endl;
        nil::actor::smp::cleanup();

        return 0;
    }

    boost::application::context &context_;
};

bool setup(boost::application::context &context) {
    return false;
}

int main(int argc, char *argv[]) {
    boost::system::error_code ec;
    /*<<Create a global context application aspect pool>>*/
    boost::application::context ctx;

    boost::application::auto_handler<prover> app(ctx);

    if (!insert_aspects(ctx, app, boost::make_shared<nil::proof::aspects::args>(argc, argv))) {
        std::cout << "[E] Application aspects configuration failed!" << std::endl;
        return 1;
    }
    if (configure_aspects(ctx, app)) {
        std::cout << "[I] Setup changed the current configuration." << std::endl;
    }
    // my server instantiation
    int result = boost::application::launch<boost::application::common>(app, ctx, ec);

    if (ec) {
        std::cout << "[E] " << ec.message() << " <" << ec.value() << "> " << std::endl;
    }

    return result;
}