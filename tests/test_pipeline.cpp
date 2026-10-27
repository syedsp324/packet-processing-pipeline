
#include <cstdint>
#include <iostream>

#include "acl.hpp"
#include "headers.hpp"
#include "routing_table.hpp"

int main() {
    RoutingTable routes;
    if (!routes.load("data/routes.txt")) {
        std::cerr << "Route loading: FAIL\n";
        return 1;
    }

    ACLFirewall firewall;

    // Allow UDP traffic to destination port 53.
    firewall.add_rule({0, 0, 0, 0, 17, 53, ACLAction::ALLOW});

    // Test packet: 192.168.1.10 -> 8.8.8.8, UDP destination port 53.
    const std::uint8_t frame[] = {
        // Ethernet header
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,

        // IPv4 header
        0x45, 0x00, 0x00, 0x1C, 0, 1, 0, 0,
        64, 17, 0, 0,
        192, 168, 1, 10,
        8, 8, 8, 8,

        // UDP header: source port 12345, destination port 53
        0x30, 0x39, 0, 53, 0, 8, 0, 0
    };

    const auto ip = parse_ipv4_frame(frame, sizeof(frame));
    if (!ip) {
        std::cerr << "IPv4 parsing: FAIL\n";
        return 1;
    }

    const auto tuple = extract_five_tuple(frame, sizeof(frame));
    if (!tuple) {
        std::cerr << "UDP tuple extraction: FAIL\n";
        return 1;
    }

    const auto action = firewall.evaluate(
        ip->src, ip->dst, ip->protocol, tuple->dst_port);

    const auto next_hop = routes.lookup(ip->dst);

    const bool allowed = action == ACLAction::ALLOW;
    const bool routed = next_hop.has_value();

    std::cout << "IPv4 parsing: PASS\n";
    std::cout << "UDP tuple extraction: PASS\n";
    std::cout << "Firewall allows DNS: "
              << (allowed ? "PASS" : "FAIL") << '\n';
    std::cout << "Route found: "
              << (routed ? "PASS" : "FAIL") << '\n';

    if (!allowed || !routed) return 1;

    std::cout << "Pipeline integration test: ALL PASSED\n";
    return 0;
}
