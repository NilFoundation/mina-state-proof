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
#include <boost/json/src.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>

#ifndef __EMSCRIPTEN__
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#endif

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
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
    using namespace nil::crypto3::marshalling;

    using proof_marshalling_type =
        nil::crypto3::marshalling::types::redshift_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>;

    auto filled_redshift_proof =
        nil::crypto3::marshalling::types::fill_redshift_proof<RedshiftProof, Endianness>(proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_redshift_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_redshift_proof.write(write_iter, cv.size());

    std::stringstream st;
    print_byteblob(st, cv.cbegin(), cv.cend());
    return st.str();
}

extern "C" {

const char *proof_gen() {
    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

    using component_type = zk::components::curve_element_unified_addition<ArithmetizationType, curve_type, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8, 9, 10>;

    typename component_type::public_params_type public_params = {};
    typename component_type::private_params_type private_params = {
        algebra::random_element<curve_type::template g1_type<>>(),
        algebra::random_element<curve_type::template g1_type<>>()};
    zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

    zk::blueprint<ArithmetizationType> bp(desc);
    zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
    zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);

    std::size_t start_row = component_type::allocate_rows(bp);
    component_type::generate_gates(bp, public_assignment, public_params, start_row);
    component_type::generate_copy_constraints(bp, public_assignment, public_params, start_row);
    component_type::generate_assignments(private_assignment, public_assignment, public_params, private_params,
                                         start_row);

    private_assignment.padding();
    public_assignment.padding();

    zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(private_assignment,
                                                                                             public_assignment);

    using params = zk::snark::redshift_params<BlueprintFieldType, ArithmetizationParams, hashes::keccak_1600<256>,
                                              hashes::keccak_1600<256>, 1>;
    using types = zk::snark::detail::redshift_policy<BlueprintFieldType, params>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType, typename params::merkle_hash_type,
                                                   typename params::transcript_hash_type, 2>;

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

    std::size_t permutation_size =
        zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams>::witness_columns +
        zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams>::public_input_columns +
        zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams>::constant_columns;

    typename types::preprocessed_public_data_type public_preprocessed_data =
        zk::snark::redshift_public_preprocessor<BlueprintFieldType, params>::process(bp, public_assignment, desc,
                                                                                     fri_params, permutation_size);
    typename types::preprocessed_private_data_type private_preprocessed_data =
        zk::snark::redshift_private_preprocessor<BlueprintFieldType, params>::process(bp, private_assignment, desc);

    auto proof = zk::snark::redshift_prover<BlueprintFieldType, params>::process(
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

//    state_type<hash_type, signature_scheme_type> state;
    std::string string;

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
        std::string line;

        while (std::getline(std::cin, line)) {
            string += line + "\n";
        }
    }
#else
//    while (std::getline(std::cin, line)) {
//        string += line + "\n";
//    }
#endif
//    {
//        boost::json::monotonic_resource mr;
//        state = boost::json::value_to<state_type<hash_type, signature_scheme_type>>(boost::json::parse(string, &mr));
//    }

#ifndef __EMSCRIPTEN__
    std::cout << proof_gen() << std::endl;
#endif
}