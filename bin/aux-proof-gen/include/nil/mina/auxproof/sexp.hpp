//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2016 Isak Andersson <bitpuffin.com>
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

#include <vector>
#include <string>
#include <cstdint>

namespace nil {
    enum class sexp_value_kind : uint8_t { SEXP, STRING };

    struct sexp_argument_iterator;

    struct sexp {
        sexp();
        sexp(std::string const &strval);
        sexp(std::vector<sexp> const &sexpval);
        sexp_value_kind kind;
        struct {
            std::vector<sexp> e;
            std::string str;
        } value;
        auto add_child(sexp sexp) -> void;
        auto add_child(const std::string &str) -> void;
        auto add_child_unescaped(std::string str) -> void;
        auto add_expression(std::string const &str) -> void;
        auto child_count() const -> size_t;
        auto get_child(size_t idx) -> sexp &;    // Call only if expr is a expr
        auto get_string() -> std::string &;
        auto get_child_by_path(std::string const &path)
            -> sexp *;    // unsafe! careful to not have the result pointer outlive the scope of the expr object
        auto create_path(std::vector<std::string> const &path) -> sexp &;
        auto create_path(std::string const &path) -> sexp &;
        auto to_string() const -> std::string;
        auto is_string() const -> bool;
        auto is_sexp() const -> bool;
        auto is_nil() const -> bool;
        auto equal(sexp const &other) const -> bool;
        auto arguments() -> sexp_argument_iterator;
        static auto unescaped(std::string strval) -> sexp;
    };

    sexp parse(std::string const &str, std::string &err);
    sexp parse(std::string const &str);
    std::string escape(std::string const &str);
    void print_should_never_reach_here();

    struct sexp_argument_iterator {
        sexp_argument_iterator(sexp &sexp);
        sexp &expr;

        typedef typename std::vector<sexp>::iterator iterator;
        typedef typename std::vector<sexp>::const_iterator const_iterator;

        iterator begin();
        iterator end();
        const_iterator begin() const;
        const_iterator end() const;
        size_t size() const;
        bool empty() const;
    };
}    // namespace nil