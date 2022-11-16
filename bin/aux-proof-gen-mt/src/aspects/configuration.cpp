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

#include <nil/aux-proof-gen-mt/aspects/configuration.hpp>

#include <boost/exception/get_error_info.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/program_options/parsers.hpp>

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
            configuration::configuration(boost::shared_ptr<path> aspct) :
                path_aspect(std::move(aspct)), cliv("Command_Line_Options"), cfgv("Configuration Options") {
            }

            void configuration::set_options(cli_options_type &cli) const {
                // clang-format off

                cli.add_options()
                    ("help,h", "Display available command-line configuration arguments")
                    ("configuration-files,c", boost::program_options::value<std::vector<std::string>>()
                            ->default_value({(path_aspect->config_path() / "config.ini").string()}),
                        "Configuration files");
                // clang-format on
            }

            void configuration::set_options(cfg_options_type &cfg) const {
            }

            void configuration::initialize(configuration_type &vm) {

                if (vm.count("help")) {
                    std::cout << cliv << std::endl;
                    return;
                }
                std::vector<std::string> confs = vm["configuration-files"].as<std::vector<std::string>>();
                std::size_t corrupted_files = 0;
                for (const std::string &file : confs) {
                    try {
                        boost::program_options::store(boost::program_options::parse_config_file(file.c_str(), cfgv),
                                                      vm);
                    } catch (const boost::program_options::reading_file &e) {
                        std::cout << e.what() << std::endl;
                        corrupted_files++;
                    } catch (const boost::program_options::error &e) {
                    }
                }

                if (corrupted_files == confs.size()) {
                    write_default_config(default_config_path());
                }
                write_default_config(default_config_path());
            }

            //            boost::program_options::variables_map &configuration::vm() {
            configuration::configuration_type &configuration::vm() {
                return vmv;
            }

            void configuration::write_default_config(const boost::filesystem::path &path) {
                boost::property_tree::ptree tree;

                for (const auto &option : cfgv.options()) {
                    std::string name = option->long_name();
                    boost::any default_value;
                    option->semantic()->apply_default(default_value);

                    if (default_value.type() == typeid(std::string)) {
                        tree.put(name, boost::any_cast<std::string>(default_value));
                    }
                }

                boost::property_tree::write_ini(path.string(), tree);
            }

            boost::filesystem::path configuration::default_config_path() const {
                return path_aspect->config_path() / "config.ini";
            }
            configuration::cli_options_type &configuration::cli() {
                return cliv;
            }
            configuration::cfg_options_type &configuration::cfg() {
                return cfgv;
            }
        }    // namespace aspects
    }        // namespace proof
}    // namespace nil
