
#include <cstdint>
#include <iostream>
#include <random>

#include "routing_table.hpp"

int main() {
    RoutingTable linear;
    TrieRoutingTable trie;

    // Load the same route table into both implementations.
    if (!linear.load("data/routes_large.txt") ||
        !trie.load("data/routes_large.txt")) {
        std::cerr << "Failed to load routing table.\n";
        return 1;
    }

    // Use a fixed seed so the test is reproducible.
    std::mt19937 rng(42);
    std::uniform_int_distribution<std::uint32_t> dist;

    constexpr int test_count = 10'000;

    for (int i = 0; i < test_count; ++i) {
        const std::uint32_t destination = dist(rng);

        const auto linear_result = linear.lookup(destination);
        const auto trie_result = trie.lookup(destination);

        // Both algorithms must return the same next hop or no route.
        if (linear_result != trie_result) {
            std::cerr << "Mismatch for destination: "
                      << destination << '\n';
            return 1;
        }
    }

    std::cout << test_count
              << " routing comparisons passed.\n";

    return 0;
}
