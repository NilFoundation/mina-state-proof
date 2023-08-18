#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

using namespace nil::crypto3;

constexpr static const std::size_t MERKLE_TREE_DEPTH = 35;
typedef hashes::poseidon hash_type;

bool operator==(typename hash_type::block_type block0,
                typename hash_type::block_type block1) {
    return block0[0] == block1[0] && block0[1] == block1[1];
}

template<std::size_t Depth = MERKLE_TREE_DEPTH, typename HashType = hash_type>
[[circuit]] bool validate_path(std::array<typename HashType::block_type, Depth> merkle_path,
                               typename HashType::block_type leaf,
                               typename HashType::block_type root) {

    typename HashType::block_type subroot = leaf;

    for (int i = 0; i < Depth; i++) {
        subroot = hash<HashType>(subroot, merkle_path[i]);
    }

    return subroot == root;
}