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
#include <boost/filesystem/string_file.hpp>
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

//#include <nil/marshalling/endianness.hpp>
//#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>

#include "ec_index_terms.hpp"

#include <fstream>

using namespace nil;
using namespace nil::crypto3;

using curve_type = nil::crypto3::algebra::curves::vesta;
using vesta_verifier_index_type = zk::snark::verifier_index<
    curve_type,
    nil::crypto3::zk::snark::arithmetic_sponge_params<curve_type::scalar_field_type::value_type>,
    nil::crypto3::zk::snark::arithmetic_sponge_params<curve_type::base_field_type::value_type>,
    nil::crypto3::zk::snark::kimchi_constant::COLUMNS,
    nil::crypto3::zk::snark::kimchi_constant::PERMUTES
    >;

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

zk::snark::proof_type<curve_type> make_proof(boost::property_tree::ptree root) {
    typename zk::snark::proof_type<curve_type> proof;
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
            for (auto &cell : row.second) {
                proof.evals[ev_i].w[i].push_back(get_cppui256(&cell));
            }
            i++;
        }

        //proof.evals[ev_i].z.size();= get_cppui256(evals_it.second.get_child("z").begin());
        for( auto z_it : evals_it.second.get_child("z") ){
            proof.evals[ev_i].z.push_back(get_cppui256(&z_it));
        }
       
        i = 0;
        for (auto &row : evals_it.second.get_child("s")) {
            for (auto &cell : row.second) {
                proof.evals[ev_i].s[i].push_back(get_cppui256(&cell));
            }
            i++;
        }

//        proof.evals[ev_i].generic_selector = get_cppui256(evals_it.second.get_child("generic_selector").begin());
        for( auto s_it : evals_it.second.get_child("generic_selector") ){
            proof.evals[ev_i].generic_selector.push_back(get_cppui256(&s_it));
        }

//        proof.evals[ev_i].poseidon_selector = get_cppui256(evals_it.second.get_child("poseidon_selector").begin());
        for( auto p_it : evals_it.second.get_child("poseidon_selector") ){
            proof.evals[ev_i].poseidon_selector.push_back(get_cppui256(&p_it));
        }
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

vesta_verifier_index_type make_verify_index(boost::property_tree::ptree root, boost::property_tree::ptree const_root) {
    using curve_type = typename nil::crypto3::algebra::curves::vesta;

    vesta_verifier_index_type ver_index;
    size_t i = 0;

    // TODO Is it right? Is it a good way to set domain generator?
    // We need to assert, need to check that the input is indeed the root of unity

    auto d_gen = multiprecision::cpp_int(const_root.get<std::string>("verify_index.domain.group_gen"));
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
    ver_index.w = multiprecision::cpp_int(const_root.get<std::string>("verify_index.w"));
    ver_index.endo = multiprecision::cpp_int(const_root.get<std::string>("verify_index.endo"));

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
void prepare_proof_scalar(zk::snark::proof_type<nil::crypto3::algebra::curves::vesta> &original_proof,
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

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType, std::size_t EvalRounds>
void prepare_proof_base(zk::snark::proof_type<nil::crypto3::algebra::curves::vesta> &original_proof,
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
        typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type point =
            algebra::random_element<typename CurveType::template g1_type<algebra::curves::coordinates::affine>>();
        public_input.push_back(point.X);
        circuit_proof.comm.table.parts[j].X =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(point.Y);
        circuit_proof.comm.table.parts[j].Y =
            var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    // OPENING PROOF
    for (std::size_t i = 0; i < original_proof.proof.lr.size(); i++) {
        assert(circuit_proof.o.L.size() > i);
        assert(circuit_proof.o.R.size() > i);
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
        typename BlueprintFieldType::value_type x  = algebra::random_element<BlueprintFieldType>();
        public_input.push_back(x);
        circuit_proof.scalars[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }
}

template<typename CurveType, typename BlueprintFieldType, typename KimchiParamsType>
void prepare_index_base(vesta_verifier_index_type &original_index,
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

    typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type point =
        algebra::random_element<typename CurveType::template g1_type<algebra::curves::coordinates::affine>>();

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
    public_input.push_back(original_index.srs.h.X);
    circuit_index.H.X = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(original_index.srs.h.Y);
    circuit_index.H.Y = var(0, public_input.size() - 1, false, var::column_type::public_input);

    for (std::size_t i = 0; i < KimchiParamsType::commitment_params_type::srs_len; i++) {
        public_input.push_back(point.X);
        circuit_index.G[i].X = var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(point.Y);
        circuit_index.G[i].Y = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    for (std::size_t i = 0; i < KimchiParamsType::public_input_size; i++) {
        public_input.push_back(original_index.srs.lagrange_bases[0][i].X);
        circuit_index.lagrange_bases[i].X = var(0, public_input.size() - 1, false, var::column_type::public_input);
        public_input.push_back(original_index.srs.lagrange_bases[0][i].Y);
        circuit_index.lagrange_bases[i].Y = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }
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

const char *generate_proof(zk::snark::pickles_proof<nil::crypto3::algebra::curves::vesta> *pickles_proof,
    vesta_verifier_index_type *pickles_index) {
#else
std::string generate_proof(zk::snark::proof_type<nil::crypto3::algebra::curves::vesta> *pickles_proof,
    vesta_verifier_index_type *pickles_index) {
#endif
    using curve_type = algebra::curves::vesta;
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
    constexpr static std::size_t max_poly_size = 32768;
    constexpr static std::size_t eval_rounds = 15;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;
    constexpr static std::size_t lookup_table_size = 0;
    constexpr static bool use_lookup = false;

    constexpr static std::size_t srs_len = 200;
    constexpr static std::size_t batch_size = 1;

    constexpr static const std::size_t prev_chal_size = 0;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    using component_type = zk::components::base_field<ArithmetizationType,
                                                      curve_type,
                                                      kimchi_params,
                                                      commitment_params,
                                                      batch_size,
                                                      0,
                                                      1,
                                                      2,
                                                      3,
                                                      4,
                                                      5,
                                                      6,
                                                      7,
                                                      8,
                                                      9,
                                                      10,
                                                      11,
                                                      12,
                                                      13,
                                                      14>;

    using fq_output_type =
        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_sponge_output;

    using fr_data_type = typename zk::components::binding<ArithmetizationType, BlueprintFieldType,
                                                          kimchi_params>::fr_data<var, batch_size>;

    using fq_data_type =
        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, kimchi_params>::fq_data<var>;

    std::size_t domain_size = 1 << 15;
    // verifier_index.domain_size = domain_size;
    // verifier_index.omega = var(0, 0, false, var::column_type::public_input);

    std::vector<typename BlueprintFieldType::value_type> public_input = {};

    std::array<zk::components::kimchi_proof_base<BlueprintFieldType, kimchi_params>, batch_size> proofs;

    for (std::size_t batch_id = 0; batch_id < batch_size; batch_id++) {
        zk::snark::proof_type<curve_type> kimchi_proof = pickles_proof[batch_id];

        zk::components::kimchi_proof_base<BlueprintFieldType, kimchi_params> proof;

        prepare_proof_base<curve_type, BlueprintFieldType, kimchi_params, eval_rounds>(kimchi_proof, proof, public_input);
    }

    zk::components::kimchi_verifier_index_base<curve_type, kimchi_params> verifier_index;
    prepare_index_base<curve_type, BlueprintFieldType, kimchi_params>(pickles_index[0], verifier_index, public_input);
    std::cout<<"pi size: "<<public_input.size()<<std::endl;

    fr_data_type fr_data_public;
    fq_data_type fq_data_public;

    typename component_type::params_type params = {proofs, verifier_index, fr_data_public, fq_data_public};

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

zk::snark::proof_type<nil::crypto3::algebra::curves::vesta> parse_proof(const char *kimchi) {
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

    vesta_verifier_index_type ver_index = make_verify_index(root, const_root);
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
    // zk::snark::proof_type<nil::crypto3::algebra::curves::vesta> proof = parse_proof(vp_input.c_str());
    // parse_pconst(vi_input.c_str(), vi_const_input.c_str());
    boost::property_tree::ptree root;
    boost::property_tree::ptree const_root;
    boost::property_tree::read_json(vm["vp_input"].as<std::string>(), root);
    boost::property_tree::read_json(vm["vi_const_input"].as<std::string>(), const_root);
    zk::snark::proof_type<nil::crypto3::algebra::curves::vesta> proof = make_proof(root);
    vesta_verifier_index_type ver_index = make_verify_index(root, const_root);

    std::cout << std::string(generate_proof(&proof, &ver_index)) << std::endl;
#endif
}
