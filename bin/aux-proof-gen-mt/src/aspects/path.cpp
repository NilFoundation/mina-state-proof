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

#include <nil/aux-proof-gen-mt/aspects/path.hpp>

#include <iostream>
namespace nil {
    namespace proof {
        namespace aspects {
            void path::initialize(configuration_type &vm) {
            }

            boost::filesystem::path path::libs_path() {
                return this->executable_path() / "../lib";
            }

            boost::filesystem::path path::libs_path(boost::system::error_code &ec) {
                return this->executable_path(ec) / "../lib";
            }
            void path::set_options(cli_options_type &cli) const {
            }
            void path::set_options(cfg_options_type &cfg) const {
            }
        }    // namespace aspects
    }        // namespace proof
}    // namespace nil