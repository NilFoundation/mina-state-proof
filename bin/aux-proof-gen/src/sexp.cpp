//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2016 Isak Andersson <bitpuffin.co>
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

#include <nil/mina/auxproof/sexp.hpp>

#include <cctype>
#include <stack>
#include <algorithm>
#include <sstream>
#include <array>
#include <iostream>

namespace nil {
    sexp::sexp() {
        this->kind = sexp_value_kind::SEXP;
    }
    sexp::sexp(std::string const &strval) {
        this->kind = sexp_value_kind::STRING;
        this->value.str = escape(strval);
    }
    sexp::sexp(std::vector<sexp> const &sexpval) {
        this->kind = sexp_value_kind::SEXP;
        this->value.e = sexpval;
    }

    auto sexp::add_child(sexp sexp) -> void {
        if (this->kind == sexp_value_kind::STRING) {
            this->kind = sexp_value_kind::SEXP;
            this->value.e.emplace_back(this->value.str);
        }
        this->value.e.push_back(std::move(sexp));
    }

    auto sexp::add_child(const std::string &str) -> void {
        this->add_child(sexp {str});
    }

    auto sexp::add_child_unescaped(std::string str) -> void {
        this->add_child(sexp::unescaped(std::move(str)));
    }

    auto sexp::add_expression(std::string const &str) -> void {
        auto err = std::string {};
        auto sexp = parse(str, err);
        if (!err.empty())
            return;
        for (auto &&c : sexp.value.e)
            this->add_child(std::move(c));
    }

    auto sexp::child_count() const -> size_t {
        switch (this->kind) {
            case sexp_value_kind::SEXP:
                return this->value.e.size();
            case sexp_value_kind::STRING:
                return 1;
        }
        print_should_never_reach_here();
        return 0;
    }

    static auto split_path_string(std::string const &path) -> std::vector<std::string> {
        auto paths = std::vector<std::string> {};
        if (path.empty())
            return paths;
        auto start = path.begin();
        for (auto i = path.begin() + 1; i != path.end(); ++i) {
            if (*i == '/') {
                paths.emplace_back(start, i);
                start = i + 1;
            }
        }
        paths.emplace_back(start, path.end());
        return paths;
    }

    auto sexp::get_child_by_path(std::string const &path) -> sexp * {
        if (this->kind == sexp_value_kind::STRING)
            return nullptr;

        auto paths = split_path_string(path);

        auto *cur = this;
        for (auto i = paths.begin(); i != paths.end();) {
            auto start = i;
            for (auto &child : cur->value.e) {
                auto brk = false;
                switch (child.kind) {
                    case sexp_value_kind::STRING:
                        if (i == paths.end() - 1 && child.value.str == *i)
                            return &child;
                        else
                            continue;
                    case sexp_value_kind::SEXP:
                        if (child.value.e.empty())
                            continue;
                        auto &fst = child.value.e[0];
                        switch (fst.kind) {
                            case sexp_value_kind::STRING:
                                if (fst.value.str == *i) {
                                    cur = &child;
                                    ++i;
                                    brk = true;
                                }
                                break;
                            case sexp_value_kind::SEXP:
                                continue;
                        }
                }
                if (brk)
                    break;
            }
            if (i == start)
                return nullptr;
            if (i == paths.end())
                return cur;
        }
        return nullptr;
    }

    static sexp *find_child(sexp &sexp, std::string name) {
        auto findPred = [&name](struct sexp &s) {
            switch (s.kind) {
                case sexp_value_kind::SEXP: {
                    if (s.child_count() == 0)
                        return false;
                    auto &hd = s.get_child(0);
                    switch (hd.kind) {
                        case sexp_value_kind::SEXP:
                            return false;
                        case sexp_value_kind::STRING:
                            return hd.get_string() == name;
                    }
                    break;
                }
                case sexp_value_kind::STRING:
                    return s.get_string() == name;
            }
            print_should_never_reach_here();
            return false;
        };
        auto loc = std::find_if(sexp.value.e.begin(), sexp.value.e.end(), findPred);
        if (loc == sexp.value.e.end())
            return nullptr;
        else
            return &(*loc);
    }

    sexp &sexp::create_path(std::vector<std::string> const &path) {
        auto el = this;
        auto nxt = el;
        auto pc = path.begin();
        for (; pc != path.end(); ++pc) {
            nxt = find_child(*el, *pc);
            if (nxt == nullptr)
                break;
            else
                el = nxt;
        }
        for (; pc != path.end(); ++pc) {
            el->add_child(sexp {std::vector<sexp> {sexp {*pc}}});
            el = &(el->get_child(el->child_count() - 1));
        }
        return *el;
    }

    sexp &sexp::create_path(std::string const &path) {
        return this->create_path(split_path_string(path));
    }

    auto sexp::get_child(size_t idx) -> sexp & {
        return this->value.e[idx];
    }

    auto sexp::get_string() -> std::string & {
        return this->value.str;
    }

    static const std::array<char, 11> escape_chars = {'\'', '"', '?', '\\', 'a', 'b', 'f', 'n', 'r', 't', 'v'};
    static const std::array<char, 11> escape_vals = {'\'', '"', '\?', '\\', '\a', '\b', '\f', '\n', '\r', '\t', '\v'};

    static auto is_escape_value(char c) -> bool {
        return std::find(escape_vals.begin(), escape_vals.end(), c) != escape_vals.end();
    }

    static auto count_escape_values(std::string const &str) -> size_t {
        return std::count_if(str.begin(), str.end(), is_escape_value);
    }

    static auto string_val_to_string(std::string const &s) -> std::string {
        if (s.size() == 0)
            return std::string {"\"\""};
        if ((std::find(s.begin(), s.end(), ' ') == s.end()) && count_escape_values(s) == 0)
            return s;
        return ('"' + escape(s) + '"');
    }

    static auto to_string_impl(sexp const &sexp, std::ostringstream &ostream) -> void {
        switch (sexp.kind) {
            case sexp_value_kind::STRING:
                ostream << string_val_to_string(sexp.value.str);
                break;
            case sexp_value_kind::SEXP:
                switch (sexp.value.e.size()) {
                    case 0:
                        ostream << "()";
                        break;
                    case 1:
                        ostream << '(';
                        to_string_impl(sexp.value.e[0], ostream);
                        ostream << ')';
                        break;
                    default:
                        ostream << '(';
                        for (auto i = sexp.value.e.begin(); i != sexp.value.e.end(); ++i) {
                            to_string_impl(*i, ostream);
                            if (i != sexp.value.e.end() - 1)
                                ostream << ' ';
                        }
                        ostream << ')';
                }
        }
    }

    auto sexp::to_string() const -> std::string {
        auto ostream = std::ostringstream {};
        // outer expr does not get surrounded by ()
        switch (this->kind) {
            case sexp_value_kind::STRING:
                ostream << string_val_to_string(this->value.str);
                break;
            case sexp_value_kind::SEXP:
                for (auto i = this->value.e.begin(); i != this->value.e.end(); ++i) {
                    to_string_impl(*i, ostream);
                    if (i != this->value.e.end() - 1)
                        ostream << ' ';
                }
        }
        return ostream.str();
    }

    auto sexp::is_string() const -> bool {
        return this->kind == sexp_value_kind::STRING;
    }

    auto sexp::is_sexp() const -> bool {
        return this->kind == sexp_value_kind::SEXP;
    }

    auto sexp::is_nil() const -> bool {
        return this->kind == sexp_value_kind::SEXP && this->child_count() == 0;
    }

    static auto children_equal(std::vector<sexp> const &a, std::vector<sexp> const &b) -> bool {
        if (a.size() != b.size())
            return false;

        for (auto i = 0u; i < a.size(); ++i) {
            if (!a[i].equal(b[i]))
                return false;
        }
        return true;
    }

    auto sexp::equal(sexp const &other) const -> bool {
        if (this->kind != other.kind)
            return false;
        switch (this->kind) {
            case sexp_value_kind::SEXP:
                return children_equal(this->value.e, other.value.e);
                break;
            case sexp_value_kind::STRING:
                return this->value.str == other.value.str;
        }
        print_should_never_reach_here();
        return false;
    }

    auto sexp::arguments() -> sexp_argument_iterator {
        return sexp_argument_iterator {*this};
    }

    auto sexp::unescaped(std::string strval) -> sexp {
        auto s = sexp {};
        s.kind = sexp_value_kind::STRING;
        s.value.str = std::move(strval);
        return s;
    }

    auto parse(std::string const &str, std::string &err) -> sexp {
        auto sexprstack = std::stack<sexp> {};
        sexprstack.push(sexp {});    // root
        auto nextiter = str.begin();
        for (auto iter = nextiter; iter != str.end(); iter = nextiter) {
            nextiter = iter + 1;
            if (std::isspace(*iter))
                continue;
            switch (*iter) {
                case '(':
                    sexprstack.push(sexp {});
                    break;
                case ')': {
                    auto topsexp = std::move(sexprstack.top());
                    sexprstack.pop();
                    if (sexprstack.empty()) {
                        err =
                            std::string {"too many ')' characters detected, closing sexprs that don't exist, no good."};
                        return sexp {};
                    }
                    auto &top = sexprstack.top();
                    top.add_child(std::move(topsexp));
                    break;
                }
                case '"': {
                    auto i = iter + 1;
                    auto start = i;
                    for (; i != str.end(); ++i) {
                        if (*i == '\\') {
                            ++i;
                            continue;
                        }
                        if (*i == '"')
                            break;
                        if (*i == '\n') {
                            err = std::string {"Unexpected newline in string literal"};
                            return sexp {};
                        }
                    }
                    if (i == str.end()) {
                        err = std::string {"Unterminated string literal"};
                        return sexp {};
                    }
                    auto resultstr = std::string {};
                    resultstr.reserve(i - start);
                    for (auto it = start; it != i; ++it) {
                        switch (*it) {
                            case '\\': {
                                ++it;
                                if (it == i) {
                                    err = std::string {"Unfinished escape sequence at the end of the string"};
                                    return sexp {};
                                }
                                auto pos = std::find(escape_chars.begin(), escape_chars.end(), *it);
                                if (pos == escape_chars.end()) {
                                    err = std::string {"invalid escape char '"} + *it + '\'';
                                    return sexp {};
                                }
                                resultstr.push_back(escape_vals[pos - escape_chars.begin()]);
                                break;
                            }
                            default:
                                resultstr.push_back(*it);
                        }
                    }
                    sexprstack.top().add_child_unescaped(std::move(resultstr));
                    nextiter = i + 1;
                    break;
                }
                case ';':
                    for (; nextiter != str.end() && *nextiter != '\n' && *nextiter != '\r'; ++nextiter) {
                    }
                    for (; nextiter != str.end() && (*nextiter == '\n' || *nextiter == '\r'); ++nextiter) {
                    }
                    break;
                default:
                    auto symend = std::find_if(iter, str.end(),
                                               [](char const &c) { return std::isspace(c) || c == ')' || c == '('; });
                    auto &top = sexprstack.top();
                    top.add_child(sexp {std::string {iter, symend}});
                    nextiter = symend;
            }
        }
        if (sexprstack.size() != 1) {
            err = std::string {"not enough s-expressions were closed by the end of parsing"};
            return sexp {};
        }
        return std::move(sexprstack.top());
    }

    auto parse(std::string const &str) -> sexp {
        auto ignored_error = std::string {};
        return parse(str, ignored_error);
    }

    auto escape(std::string const &str) -> std::string {
        auto escape_count = count_escape_values(str);
        if (escape_count == 0)
            return str;
        auto result_str = std::string {};
        result_str.reserve(str.size() + escape_count);
        for (auto c : str) {
            auto loc = std::find(escape_vals.begin(), escape_vals.end(), c);
            if (loc == escape_vals.end())
                result_str.push_back(c);
            else {
                result_str.push_back('\\');
                result_str.push_back(escape_chars[loc - escape_vals.begin()]);
            }
        }
        return result_str;
    }

    auto print_should_never_reach_here() -> void {
        std::cerr << "Error: Should never reach here " << __FILE__ << ": " << __LINE__ << std::endl;
    }

    sexp_argument_iterator::sexp_argument_iterator(sexp &sexp) : expr(sexp) {
    }

    sexp_argument_iterator::iterator sexp_argument_iterator::begin() {
        if (this->size() == 0)
            return this->end();
        else
            return ++(this->expr.value.e.begin());
    }

    sexp_argument_iterator::iterator sexp_argument_iterator::end() {
        return this->expr.value.e.end();
    }

    sexp_argument_iterator::const_iterator sexp_argument_iterator::begin() const {
        if (this->size() == 0)
            return this->end();
        else
            return ++(this->expr.value.e.begin());
    }

    sexp_argument_iterator::const_iterator sexp_argument_iterator::end() const {
        return this->expr.value.e.end();
    }

    auto sexp_argument_iterator::empty() const -> bool {
        return this->size() == 0;
    }

    auto sexp_argument_iterator::size() const -> size_t {
        auto sz = this->expr.value.e.size();
        if (sz == 0)
            return 0;
        else
            return sz - 1;
    }
}    // namespace nil