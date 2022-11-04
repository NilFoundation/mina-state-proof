//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the Server Side Public License, version 1,
// as published by the author.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// Server Side Public License for more details.
//
// You should have received a copy of the Server Side Public License
// along with this program. If not, see
// <https://github.com/NilFoundation/dbms/blob/master/LICENSE_1_0.txt>.
//---------------------------------------------------------------------------//

#include <nil/aux-proof-gen-mt/aspects/proof.hpp>

#include <boost/exception/get_error_info.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/filesystem.hpp>

namespace std {
    template<typename CharT, typename TraitsT>
    std::basic_ostream<CharT, TraitsT> &operator<<(std::basic_ostream<CharT, TraitsT> &out,
                                                   const std::vector<std::string> &xs) {
        return out << std::accumulate(
                   std::next(xs.begin()), xs.end(), xs[0],
                   [](std::string a, const std::string &b) -> std::string { return std::move(a) + ';' + b; });
    }
}    // namespace std

namespace nil {
    namespace proof {
        namespace aspects {
            proof::proof(boost::shared_ptr<path> aspct) : path_aspect(std::move(aspct)) {
            }

            void proof::set_options(cli_options_type &cli) const {
                boost::program_options::options_description options("Mina AUX Proof Generator");
                // clang-format off
                options.add_options()
                ("version,v", "Display version")
                ("output,o", boost::program_options::value<std::string>(),"Output file")
                ("vi_input", boost::program_options::value<std::string>(), "Input index file")
                ("vi_const_input", boost::program_options::value<std::string>(), "Input const index file")
                ("scalar_proof", boost::program_options::bool_switch()->default_value(false), "Generate scalar part of the circuit")
                ("base_proof", boost::program_options::bool_switch()->default_value(false), "Generate base part of the circuit")
                ("max_step", boost::program_options::value<std::size_t>()->default_value(3), "Step for FRI folding (default 3)");
                // clang-format on
                cli.add(options);
            }

            void proof::set_options(cfg_options_type &cfg) const {
                boost::program_options::options_description options("Mina AUX Proof Generator");
                // clang-format off
                options.add_options()
                ("version,v", "Display version")
                ("output,o", boost::program_options::value<std::string>(),"Output file")
                ("vi_input", boost::program_options::value<std::string>(), "Input index file")
                ("vi_const_input", boost::program_options::value<std::string>(), "Input const index file")
                ("scalar_proof", boost::program_options::bool_switch()->default_value(false), "Generate scalar part of the circuit")
                ("base_proof", boost::program_options::bool_switch()->default_value(false), "Generate base part of the circuit")
                ("max_step", boost::program_options::value<std::size_t>()->default_value(3), "Step for FRI folding (default 3)");
                // clang-format on
                cfg.add(options);
            }

            void proof::initialize(configuration_type &vm) {
//                if (vm.count("vi_input")) {
//                    if (vm["vi_input"].as<std::string>().size() < PATH_MAX ||
//                        vm["vi_input"].as<std::string>().size() < FILENAME_MAX) {
//                        if (boost::filesystem::exists(vm["input"].as<std::string>())) {
//                            boost::filesystem::load_string_file(vm["input"].as<std::string>(), vi_input);
//                        }
//                    } else {
//                        vi_input = vm["vi_input"].as<std::string>();
//                    }
//                } else {
//                    std::string line;
//
//                    while (std::getline(std::cin, line)) {
//                        vi_input += line + "\n";
//                    }
//                }
//
//                if (vm.count("vi_const_input")) {
//                    if (vm["vi_const_input"].as<std::string>().size() < PATH_MAX ||
//                        vm["vi_const_input"].as<std::string>().size() < FILENAME_MAX) {
//                        if (boost::filesystem::exists(vm["vi_const_input"].as<std::string>())) {
//                            boost::filesystem::load_string_file(vm["vi_const_input"].as<std::string>(), vi_input);
//                        }
//                    } else {
//                        vi_const_input = vm["vi_input"].as<std::string>();
//                    }
//                } else {
//                    std::string line;
//
//                    while (std::getline(std::cin, line)) {
//                        vi_const_input += line + "\n";
//                    }
//                }
            }

            boost::filesystem::path proof::default_config_path() const {
                return path_aspect->config_path() / "config.ini";
            }

            std::string proof::input_string() const {
                return json_string;
            }
        }    // namespace aspects
    }        // namespace proof
}    // namespace nil
