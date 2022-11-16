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

#ifndef PROOF_PATH_ASPECT_HPP
#define PROOF_PATH_ASPECT_HPP

#include <boost/application/aspects/path.hpp>

#include <nil/aux-proof-gen-mt/detail/configurable.hpp>

#include <nil/dbms/plugin/options_description.hpp>
#include <nil/dbms/plugin/variables_map.hpp>

namespace std {
    template<>
    struct hash<boost::filesystem::path> {
        inline std::size_t operator()(const boost::filesystem::path &p) const {
            return std::hash<std::string>()(p.string());
        }
    };
}    // namespace std

namespace nil {
    namespace proof {
        namespace aspects {
            struct path
                : public boost::application::path,
                  public detail::configurable<dbms::plugin::variables_map, dbms::plugin::cli_options_description,
                                              dbms::plugin::cfg_options_description> {
                typedef detail::configurable<dbms::plugin::variables_map, dbms::plugin::cli_options_description,
                                             dbms::plugin::cfg_options_description>
                    policy_type;

                typedef typename policy_type::options_types options_type;
                typedef typename policy_type::configuration_type configuration_type;

                typedef typename std::tuple_element<0, options_type>::type cli_options_type;
                typedef typename std::tuple_element<1, options_type>::type cfg_options_type;

                virtual void set_options(cli_options_type &cli) const override;
                virtual void set_options(cfg_options_type &cfg) const override;
                virtual void initialize(configuration_type &vm) override;

                boost::filesystem::path libs_path();

                boost::filesystem::path libs_path(boost::system::error_code &ec);
            };
        }    // namespace aspects
    }        // namespace proof
}    // namespace nil

#endif    // DBMS_ARGS_HPP
