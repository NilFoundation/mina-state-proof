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

#include <nil/aux-proof-gen-mt/aspects/args.hpp>

namespace nil {
    namespace proof {
        namespace aspects {
            args::args(int argc, char **argv) : args_(argc, argv) {
            }

            void args::set_options(cli_options_type &cli) const {
            }

            void args::set_options(cfg_options_type &cfg) const {
            }

            void args::initialize(configuration_type &vm) {
            }
        }    // namespace aspects
    }        // namespace proof
}    // namespace nil
