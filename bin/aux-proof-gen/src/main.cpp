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

#include <iostream>

#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>

#ifndef __EMSCRIPTEN__
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#endif

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/alt_bn128.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>

#include <nil/crypto3/zk/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_endo_scalar_mul_15_wires.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/crypto3/zk/algorithms/generate.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>

#include <nil/crypto3/zk/math/non_linear_combination.hpp>

#include <nil/mina/auxproof/sexp.hpp>

using namespace nil;
using namespace nil::crypto3;

typedef algebra::curves::alt_bn128<254> curve_type;
typedef typename curve_type::base_field_type field_type;
constexpr static const std::size_t m = 2;
constexpr static const std::size_t k = 1;

constexpr static const std::size_t table_rows_log = 4;
constexpr static const std::size_t table_rows = 1 << table_rows_log;
constexpr static const std::size_t permutation_size = 4;
constexpr static const std::size_t usable_rows = 1 << table_rows_log;

struct redshift_params {
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 1;
    constexpr static const std::size_t constant_columns = 0;
    constexpr static const std::size_t selector_columns = 2;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

constexpr static const std::size_t table_columns =
    redshift_params::witness_columns + redshift_params::public_input_columns;

typedef zk::commitments::fri<field_type, redshift_params::merkle_hash_type, redshift_params::transcript_hash_type, m>
    fri_type;

typedef zk::snark::redshift_params<field_type, redshift_params::witness_columns, redshift_params::public_input_columns,
                                   redshift_params::constant_columns, redshift_params::selector_columns>
    circuit_params;

int main(int argc, char *argv[]) {
#ifndef __EMSCRIPTEN__
    boost::program_options::options_description options("Mina State Auxiliary Proof Generator");
    // clang-format off
    options.add_options()("help,h", "Display help message")
    ("version,v", "Display version")
    ("proof", boost::program_options::value<std::string>(), "Proof contents or path");
    // clang-format on

    boost::program_options::positional_options_description p;
    p.add("proof", 1);

    boost::program_options::variables_map vm;
    boost::program_options::store(
        boost::program_options::command_line_parser(argc, argv).options(options).positional(p).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << options << std::endl;
        return 0;
    }

    std::string err {};
    sexp s;
    if (vm.count("proof")) {
        if (boost::filesystem::exists(vm["proof"].as<std::string>())) {
            std::string string;
            boost::filesystem::load_string_file(vm["proof"].as<std::string>(), string);
            s = parse(string, err);
        } else {
            s = parse(vm["proof"].as<std::string>(), err);
        }
    } else {
        std::string string;
        std::cin >> string;
        s = parse(string, err);
    }

#else
    std::string string;
    std::cin >> string;
    s = parse(string, err);
#endif

    if (!err.empty()) {
    }

    constexpr typename curve_type::template g1_type<>::value_type B = curve_type::template g1_type<>::value_type::one();
    using ArithmetizationType = zk::snark::plonk_constraint_system<field_type>;

    zk::snark::pickles_proof<curve_type, redshift_params::witness_columns> state_proof;

    zk::blueprint<ArithmetizationType> bp;
    zk::blueprint_private_assignment_table<ArithmetizationType, redshift_params::witness_columns> private_assignment;
    zk::blueprint_public_assignment_table<ArithmetizationType, redshift_params::public_input_columns,
                                          redshift_params::constant_columns, redshift_params::selector_columns>
        public_assignment;

    zk::components::curve_element_variable_base_endo_scalar_mul<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5, 6, 7,
                                                                8, 9, 10, 11, 12, 13, 14>
        scalar_mul_component(bp);
    zk::components::poseidon_plonk<ArithmetizationType, curve_type> poseidon_component(bp);

    scalar_mul_component.generate_gates(public_assignment);
    poseidon_component.generate_gates();

    typename curve_type::scalar_field_type::value_type a = curve_type::scalar_field_type::value_type::one();
    typename curve_type::template g1_type<>::value_type P = curve_type::template g1_type<>::value_type::one();

    scalar_mul_component.generate_assignments(private_assignment, public_assignment, {P, a});
    poseidon_component.generate_assignments();

    auto cs = bp.get_constraint_system();

    auto assignments = bp.full_variable_assignment();

    typedef zk::snark::redshift_preprocessor<typename curve_type::base_field_type, 15, 1> preprocessor_type;
    typedef zk::snark::redshift_prover<typename curve_type::base_field_type, 15, 5, 1, 5> prover_type;

    auto proof = prover_type::process(preprocessor_type::process(cs, assignments), cs, assignments);

#ifndef __EMSCRIPTEN__
    if (vm.count("output")) {
    }
#else

#endif

    return 0;
}