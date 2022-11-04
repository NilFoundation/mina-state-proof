//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#include <nil/aux-proof-gen-mt/aspects/actor.hpp>

#include <nil/actor/detail/log-cli.hh>
#include <nil/actor/core/reactor.hh>
#include <nil/actor/core/scollectd.hh>
#include <nil/actor/core/metrics_api.hh>

namespace nil {
    namespace proof {
        namespace aspects {
            struct config {
                nil::actor::sstring name = "App";
                nil::actor::sstring description = "";
                std::chrono::duration<double> default_task_quota = std::chrono::microseconds(500);
                bool auto_handle_sigint_sigterm = true;

                config() {
                }
            };

            static nil::actor::reactor_config reactor_config_from_app_config(config cfg) {
                nil::actor::reactor_config ret;
                ret.auto_handle_sigint_sigterm = cfg.auto_handle_sigint_sigterm;
                ret.task_quota = cfg.default_task_quota;
                return ret;
            };

            actor::actor(boost::shared_ptr<path> aspct) : path_aspect(std::move(aspct)) {
            }

            void actor::initialize(configuration_type &vm) {
                if (vm["help-loggers"].as<bool>()) {
                    nil::actor::log_cli::print_available_loggers(std::cout);
                    exit(1);
                }

                try {
                    boost::program_options::notify(vm);
                } catch (const boost::program_options::required_option &ex) {
                    std::cerr << ex.what() << std::endl;
                    exit(1);
                }

                // Needs to be before `smp::configure()`.
                try {
                    apply_logging_settings(nil::actor::log_cli::extract_settings(vm));
                } catch (const std::runtime_error &exn) {
                    std::cerr << "logging configuration error: " << exn.what() << '\n';
                    exit(1);
                }

                try {
                    nil::actor::smp::configure(vm, reactor_config_from_app_config(config()));
                } catch (...) {
                    std::cerr << "Could not initialize actor: " << std::current_exception() << std::endl;
                    exit(1);
                }
                //                vm.emplace("argv0", boost::program_options::variable_value(std::string(av[0]),
                //                false));
            }

            void actor::set_options(cli_options_type &cli) const {
                boost::program_options::options_description _opts("Actor");

                // configure
                //                _opts.add_options()("help,h", "show help message");

                nil::actor::smp::register_network_stacks();
                _opts.add(nil::actor::reactor::get_options_description(reactor_config_from_app_config(config())));
                _opts.add(nil::actor::metrics::get_options_description());
                _opts.add(nil::actor::smp::get_options_description());
                _opts.add(nil::actor::scollectd::get_options_description());
                _opts.add(nil::actor::log_cli::get_options_description());

                cli.add(_opts);
            }

            void actor::set_options(cfg_options_type &cfg) const {
                boost::program_options::options_description _opts("Actor");

                nil::actor::smp::register_network_stacks();
                _opts.add(nil::actor::reactor::get_options_description(reactor_config_from_app_config(config())));
                _opts.add(nil::actor::metrics::get_options_description());
                _opts.add(nil::actor::smp::get_options_description());
                _opts.add(nil::actor::scollectd::get_options_description());
                _opts.add(nil::actor::log_cli::get_options_description());

                cfg.add(_opts);
            }
        }    // namespace aspects
    }        // namespace proof
}    // namespace nil
