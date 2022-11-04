//---------------------------------------------------------------------------//
// Copyright (c) 2018-2022 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef PROOF_DETAIL_CONFIGURABLE_HPP
#define PROOF_DETAIL_CONFIGURABLE_HPP

#include <tuple>

namespace nil {
    namespace proof {
        namespace detail {
            template<typename ConfigurationType, typename OptionsTypes1, typename OptionsTypes2>
            struct configurable {
                typedef std::tuple<OptionsTypes1, OptionsTypes2> options_types;

                typedef ConfigurationType configuration_type;

                virtual void set_options(OptionsTypes1 &cfg) const = 0;
                virtual void set_options(OptionsTypes2 &cfg) const = 0;
                virtual void initialize(configuration_type &options) = 0;
            };
        }    // namespace detail
    }        // namespace proof
}    // namespace nil

#endif    // PROOF_DETAIL_CONFIGURABLE_HPP
