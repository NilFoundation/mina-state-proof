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

#include <nil/crypto3/zk/snark/systems/plonk/pickles/proof.hpp>

#include <nil/mina/auxproof/sexp.hpp>

using namespace nil;

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

    if (vm.count("proof")) {
        if (boost::filesystem::exists(vm["proof"].as<std::string>())) {
            std::string string;
            boost::filesystem::load_string_file(vm["proof"].as<std::string>(), string);
            sexp s = parse(string);
        } else {
            sexp s = parse(vm["proof"].as<std::string>());
        }
    }
#else
    std::string string;
    std::cin >> string;
    sexp s = parse(string);
#endif
    return 0;
}