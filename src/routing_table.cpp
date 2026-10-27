
#include "routing_table.hpp"
#include "headers.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

// Convert dotted IPv4 text to a 32-bit number.
static bool parse_ip(const std::string& text, std::uint32_t& ip) {
    unsigned a, b, c, d;
    char dot1, dot2, dot3;
    std::istringstream in(text);

    if (!(in >> a >> dot1 >> b >> dot2 >> c >> dot3 >> d) ||
        dot1 != '.' || dot2 != '.' || dot3 != '.' ||
        a > 255 || b > 255 || c > 255 || d > 255)
        return false;

    // Reject trailing characters after the IPv4 address.
    in >> std::ws;
    if (!in.eof()) return false;

    ip = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

// Load routes from a file containing: network/prefix next_hop
bool RoutingTable::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) return false;

    routes_.clear();
    std::string line;

    while (std::getline(file, line)) {
        // Skip blank lines and comments.
        std::istringstream in(line);
        std::string cidr, hop, extra;

        if (!(in >> cidr)) continue;
        if (cidr[0] == '#') continue;

        if (!(in >> hop) || (in >> extra)) {
            routes_.clear();
            return false;
        }

        const auto slash = cidr.find('/');
        if (slash == std::string::npos) {
            routes_.clear();
            return false;
        }

        std::uint32_t network, next_hop;
        unsigned prefix;

        if (!parse_ip(cidr.substr(0, slash), network) ||
            !parse_ip(hop, next_hop)) {
            routes_.clear();
            return false;
        }

        try {
            std::size_t used = 0;
            prefix = std::stoul(cidr.substr(slash + 1), &used);

            if (used != cidr.size() - slash - 1 || prefix > 32) {
                routes_.clear();
                return false;
            }
        } catch (...) {
            routes_.clear();
            return false;
        }

        // Normalize the network address to its prefix.
        const std::uint32_t mask =
            prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));

        routes_.push_back({
            network & mask,
            next_hop,
            static_cast<std::uint8_t>(prefix)
        });
    }

    return !routes_.empty() && file.eof();
}

// Return the loaded routes for trie construction.
const std::vector<Route>& RoutingTable::routes() const {
    return routes_;
}

// Find the next hop using linear longest-prefix matching.
std::optional<std::uint32_t> RoutingTable::lookup(
    std::uint32_t destination) const {

    const Route* best = nullptr;

    for (const auto& route : routes_) {
        const std::uint32_t mask =
            route.prefix_length == 0
                ? 0u
                : (0xFFFFFFFFu << (32 - route.prefix_length));

        if ((destination & mask) == route.network &&
            (!best || route.prefix_length > best->prefix_length)) {
            best = &route;
        }
    }

    if (!best) return std::nullopt;
    return best->next_hop;
}

// Create an empty binary trie.
TrieRoutingTable::TrieRoutingTable() : root_(new Node{}) {}

// Free trie memory when the object is destroyed.
TrieRoutingTable::~TrieRoutingTable() {
    destroy(root_);
}

// Recursively free a node and its children.
void TrieRoutingTable::destroy(Node* node) {
    if (!node) return;

    destroy(node->child[0]);
    destroy(node->child[1]);
    delete node;
}

// Load routes and insert their prefix bits into the trie.
bool TrieRoutingTable::load(const std::string& filename) {
    // Reuse the linear router's route-file parser.
    RoutingTable linear;
    if (!linear.load(filename)) return false;

    // Start with an empty trie.
    destroy(root_);
    root_ = new Node{};

    for (const auto& route : linear.routes()) {
        Node* node = root_;

        // Insert bits from most significant to least significant.
        for (int bit = 31; bit >= 32 - route.prefix_length; --bit) {
            const unsigned direction = (route.network >> bit) & 1u;

            if (!node->child[direction])
                node->child[direction] = new Node{};

            node = node->child[direction];
        }

        // Store the next hop at the end of this prefix.
        node->has_route = true;
        node->next_hop = route.next_hop;
    }

    return true;
}

// Find the next hop by following destination bits through the trie.
std::optional<std::uint32_t> TrieRoutingTable::lookup(
    std::uint32_t destination) const {

    const Node* node = root_;
    std::optional<std::uint32_t> best;

    // The root may contain the default route (0.0.0.0/0).
    if (node->has_route)
        best = node->next_hop;

    // Remember the deepest matching prefix.
    for (int bit = 31; bit >= 0; --bit) {
        const unsigned direction = (destination >> bit) & 1u;
        node = node->child[direction];

        if (!node) break;

        if (node->has_route)
            best = node->next_hop;
    }

    return best;
}
