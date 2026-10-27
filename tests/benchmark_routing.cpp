
#include <chrono>
#include <cstdint>
#include <iostream>
#include <random>
#include <vector>

#include "routing_table.hpp"

int main() {
    RoutingTable linear;
    TrieRoutingTable trie;

    if (!linear.load("data/routes_large.txt") ||
        !trie.load("data/routes_large.txt")) {
        std::cerr << "Failed to load routing table.\n";
        return 1;
    }

    constexpr std::size_t NUM_LOOKUPS = 1'000'000;
    std::vector<std::uint32_t> destinations;
    destinations.reserve(NUM_LOOKUPS);

    std::mt19937 rng(42);
    for (std::size_t i = 0; i < NUM_LOOKUPS; ++i) {
        destinations.push_back(rng());
    }

    // Warm up both implementations.
    for (std::size_t i = 0; i < 1000; ++i) {
        linear.lookup(destinations[i]);
        trie.lookup(destinations[i]);
    }

    // Verify identical results before timing.
    for (const auto destination : destinations) {
        if (linear.lookup(destination) != trie.lookup(destination)) {
            std::cerr << "Routing mismatch detected.\n";
            return 1;
        }
    }

    volatile std::uint64_t checksum = 0;

    const auto linear_start = std::chrono::steady_clock::now();
    for (const auto destination : destinations) {
        const auto result = linear.lookup(destination);
        if (result) checksum += *result;
    }
    const auto linear_end = std::chrono::steady_clock::now();

    const auto trie_start = std::chrono::steady_clock::now();
    for (const auto destination : destinations) {
        const auto result = trie.lookup(destination);
        if (result) checksum += *result;
    }
    const auto trie_end = std::chrono::steady_clock::now();

    const auto linear_ms =
        std::chrono::duration<double, std::milli>(
            linear_end - linear_start).count();

    const auto trie_ms =
        std::chrono::duration<double, std::milli>(
            trie_end - trie_start).count();

    std::cout << "Routes loaded: " << NUM_LOOKUPS
              << " destination lookups\n";
    std::cout << "Linear lookup: " << linear_ms << " ms\n";
    std::cout << "Trie lookup:   " << trie_ms << " ms\n";

    if (trie_ms > 0.0) {
        std::cout << "Speedup:       "
                  << linear_ms / trie_ms << "x\n";
    }

    std::cout << "Checksum: " << checksum << '\n';
    return 0;
}
