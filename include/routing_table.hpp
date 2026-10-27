#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Represents one IPv4 route.
struct Route {
    std::uint32_t network{};
    std::uint32_t next_hop{};
    std::uint8_t prefix_length{};
};

class RoutingTable {
public:
    // Load routes from the route file.
    bool load(const std::string& filename);

    // Return the next hop for the best matching route.
    std::optional<std::uint32_t> lookup(std::uint32_t destination) const;

    // Expose routes for trie construction.
    const std::vector<Route>& routes() const;

private:
    std::vector<Route> routes_;
};

class TrieRoutingTable {
public:
    TrieRoutingTable();
    ~TrieRoutingTable();

    // Disable copying to avoid double-free.
    TrieRoutingTable(const TrieRoutingTable&) = delete;
    TrieRoutingTable& operator=(const TrieRoutingTable&) = delete;

    // Load routes into the trie.
    bool load(const std::string& filename);

    // Return the next hop for the best matching route.
    std::optional<std::uint32_t> lookup(std::uint32_t destination) const;

private:
    // Each node represents a bit in an IPv4 address.
    struct Node {
        Node* child[2]{};
        bool has_route{false};
        std::uint32_t next_hop{};
    };

    Node* root_;

    // Free all nodes in the trie.
    static void destroy(Node* node);
};