##---------------------------------------------------------------------------##
## Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
##
## MIT License
##
## Permission is hereby granted, free of charge, to any person obtaining a copy
## of this software and associated documentation files (the "Software"), to deal
## in the Software without restriction, including without limitation the rights
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is
## furnished to do so, subject to the following conditions:
##
## The above copyright notice and this permission notice shall be included in all
## copies or substantial portions of the Software.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
## SOFTWARE.
##---------------------------------------------------------------------------##

def parse_to_binary_list(expr: str):
    bin_start_id = expr.find("[")
    bins = []
    while (bin_start_id != -1):
        found_simple = False
        first_start = expr.find("[", bin_start_id + 1)
        first_end = expr.find("]", bin_start_id + 1) # LAST CONDITION
        if (first_start == -1 and first_end == -1):
            return bins
        if (first_start > first_end) or (first_start == -1):
            var = "tmp_" + repr(len(bins))
            bins.append(var + " = " + expr[bin_start_id : first_end + 1])
            expr = expr.replace(expr[bin_start_id : first_end + 1], var)
            bin_start_id = 0
        else:
            bin_start_id = expr.find("[", bin_start_id + 1) 

def bin_to_component(expr: str):
    components_map = {"*" : "mul_component", "+" : "add_component", "-" : "sub_component"}
    component_name = ""
    op_id = 0
    for op in components_map:
        if expr.find(op) > -1:
            component_name = components_map[op]
            op_id = expr.find(op)
    var_out = "var " + expr[:expr.find("=")]
    var1 = expr[expr.find("=") + 3 : op_id - 1]
    var2 = expr[op_id + 1 : -1]
    res = var_out + " = " + component_name + "::generate_assignments(assignment, {" + var1 + ", " + var2 + "}, row).output;\n"
    res = res + "row += {}::rows_amount;\n".format(component_name)
    return res


def parse_expr(expr: str):
    res = ""
    # separate caches
    cache_map = {}
    cache_pos = expr.find("CacheId", 0)
    while(cache_pos != -1):
        start_idx = cache_pos - 1
        last_idx = expr.find("|", start_idx + 1)
        cache_id_last = expr.find(")", start_idx)
        cache_id = expr[cache_pos + 8 : cache_id_last]
        if cache_id not in cache_map:
            cache_map[cache_id] = [expr[start_idx : last_idx + 1], "cache_" + cache_id]
        expr = expr.replace(expr[start_idx : last_idx + 1], cache_map[cache_id][1])
        cache_pos = expr.find("CacheId", 0)

    # format vars
    expr = expr.replace("Curr", "0")
    expr = expr.replace("Next", "+1")
    for i in range(0, 15):
        target = "Witness(" + repr(i) + ")"
        expr = expr.replace(target, "W" + repr(i))
    
    # split expressions to the set of binary operations
    bins = parse_to_binary_list(expr)
    bins.reverse()

    # add bins to the res
    for bin_op in bins:
        component_notation = bin_to_component(bin_op)
        res = component_notation + "\n" + res

    # add caches to the result
    for cache_id in cache_map:
        res = cache_map[cache_id][1] + " = " + cache_map[cache_id][0] + "\n" + res
    
    return res

#expr = "(var(Index(CompleteAdd), Curr) * ((((((((var(Witness(10), Curr) * [CacheId(0), (var(Witness(2), Curr) - var(Witness(0), Curr))]) - (0x0000000000000000000000000000000000000000000000000000000000000001_ccpui256 - var(Witness(7), Curr))) + (Pow(Alpha, 1) * (var(Witness(7), Curr) * [CacheId(0), (var(Witness(2), Curr) - var(Witness(0), Curr))]))) + (Pow(Alpha, 2) * ((var(Witness(7), Curr) * ((((2 * var(Witness(8), Curr)) * var(Witness(1), Curr)) - (2 * [CacheId(2), (var(Witness(0), Curr) * var(Witness(0), Curr))])) - [CacheId(2), (var(Witness(0), Curr) * var(Witness(0), Curr))])) + ((0x0000000000000000000000000000000000000000000000000000000000000001_ccpui256 - var(Witness(7), Curr)) * (([CacheId(0), (var(Witness(2), Curr) - var(Witness(0), Curr))] * var(Witness(8), Curr)) - [CacheId(1), (var(Witness(3), Curr) - var(Witness(1), Curr))]))))) + (Pow(Alpha, 3) * (((var(Witness(0), Curr) + var(Witness(2), Curr)) + var(Witness(4), Curr)) - (var(Witness(8), Curr) * var(Witness(8), Curr))))) + (Pow(Alpha, 4) * (((var(Witness(8), Curr) * (var(Witness(0), Curr) - var(Witness(4), Curr))) - var(Witness(1), Curr)) - var(Witness(5), Curr)))) + (Pow(Alpha, 5) * ([CacheId(1), (var(Witness(3), Curr) - var(Witness(1), Curr))] * (var(Witness(7), Curr) - var(Witness(6), Curr))))) + (Pow(Alpha, 6) * (([CacheId(1), (var(Witness(3), Curr) - var(Witness(1), Curr))] * var(Witness(9), Curr)) - var(Witness(6), Curr)))))"
expr = "[var(Index(CompleteAdd), Curr) * [[[[[[[[var(Witness(10), Curr) * |CacheId(0), [var(Witness(2), Curr) - var(Witness(0), Curr)]|] - [0x0000000000000000000000000000000000000000000000000000000000000001_ccpui256 - var(Witness(7), Curr)]] + [Pow(Alpha, 1) * [var(Witness(7), Curr) * |CacheId(0), [var(Witness(2), Curr) - var(Witness(0), Curr)]|]]] + [Pow(Alpha, 2) * [[var(Witness(7), Curr) * [[[[var(Witness(8), Curr) + var(Witness(8), Curr)] * var(Witness(1), Curr)] - [|CacheId(2), [var(Witness(0), Curr) * var(Witness(0), Curr)]| + |CacheId(2), [var(Witness(0), Curr) * var(Witness(0), Curr)]|]] - |CacheId(2), [var(Witness(0), Curr) * var(Witness(0), Curr)]|]] + [[0x0000000000000000000000000000000000000000000000000000000000000001_ccpui256 - var(Witness(7), Curr)] * [[|CacheId(0), [var(Witness(2), Curr) - var(Witness(0), Curr)]| * var(Witness(8), Curr)] - |CacheId(1), [var(Witness(3), Curr) - var(Witness(1), Curr)]|]]]]] + [Pow(Alpha, 3) * [[[var(Witness(0), Curr) + var(Witness(2), Curr)] + var(Witness(4), Curr)] - [var(Witness(8), Curr) * var(Witness(8), Curr)]]]] + [Pow(Alpha, 4) * [[[var(Witness(8), Curr) * [var(Witness(0), Curr) - var(Witness(4), Curr)]] - var(Witness(1), Curr)] - var(Witness(5), Curr)]]] + [Pow(Alpha, 5) * [|CacheId(1), [var(Witness(3), Curr) - var(Witness(1), Curr)]| * [var(Witness(7), Curr) - var(Witness(6), Curr)]]]] + [Pow(Alpha, 6) * [[|CacheId(1), [var(Witness(3), Curr) - var(Witness(1), Curr)]| * var(Witness(9), Curr)] - var(Witness(6), Curr)]]]]"
print(parse_expr(expr))