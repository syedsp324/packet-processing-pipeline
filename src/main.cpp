
#include <iostream>

#include "pcap_reader.hpp"
#include "headers.hpp"
#include "routing_table.hpp"
#include "acl.hpp"

int main() {
    // Load the routing table.
    RoutingTable routes;
    if (!routes.load("data/routes.txt")) {
        std::cerr << "Error: Could not load routing table.\n";
        return 1;
    }

    // Configure the ACL firewall.
    ACLFirewall firewall;

    // Rule 1: Deny UDP traffic to destination port 53.
    // Allow UDP DNS traffic in this test capture.
    firewall.add_rule({
        0, 0,       // Any source IP
        0, 0,       // Any destination IP
        17,         // UDP
        53,         // Destination port
        ACLAction::ALLOW
    });

    // Rule 2: Allow UDP traffic to destination port 443.
    firewall.add_rule({
        0, 0,       // Any source IP
        0, 0,       // Any destination IP
        17,         // UDP
        443,        // Destination port
        ACLAction::ALLOW
    });

    // Unmatched packets are denied by ACLFirewall::evaluate().

    // Open the real DNS capture.
    PcapReader reader("data/traces/dns.cap");
    if (!reader.is_open()) {
        std::cerr << "Error: Could not open data/traces/dns.cap\n";
        return 1;
    }

    PcapPacket packet;
    int packet_number = 0;
    int allowed_count = 0;
    int denied_count = 0;
    int routed_count = 0;
    int invalid_count = 0;

    // Read and process every captured packet.
    while (reader.next(packet)) {
        ++packet_number;
        std::cout << "\nPacket " << packet_number << ":\n";

        // Parse the Ethernet frame and IPv4 header.
        const auto ip = parse_ipv4_frame(
            packet.data.data(), packet.data.size()
        );

        if (!ip) {
            ++invalid_count;
            std::cout << "  Invalid or unsupported IPv4 packet\n";
            continue;
        }

        std::cout << "  Source:      " << ipv4_to_string(ip->src) << '\n';
        std::cout << "  Destination: " << ipv4_to_string(ip->dst) << '\n';
        std::cout << "  Protocol:    "
                  << static_cast<int>(ip->protocol) << '\n';

        // Extract TCP/UDP ports when available.
        const auto tuple = extract_five_tuple(
            packet.data.data(), packet.data.size()
        );

        std::uint16_t dst_port = 0;

        if (tuple) {
            dst_port = tuple->dst_port;
            std::cout << "  Source port: " << tuple->src_port << '\n';
            std::cout << "  Destination port: " << tuple->dst_port << '\n';
        } else {
            std::cout << "  No TCP/UDP ports extracted\n";
        }

        // Apply the first matching ACL rule.
        const ACLAction action = firewall.evaluate(
            ip->src, ip->dst, ip->protocol, dst_port
        );

        if (action == ACLAction::DENY) {
            ++denied_count;
            std::cout << "  Firewall: DENY\n";
            continue;
        }

        ++allowed_count;
        std::cout << "  Firewall: ALLOW\n";

        // Route only packets permitted by the firewall.
        const auto next_hop = routes.lookup(ip->dst);

        if (next_hop) {
            ++routed_count;
            std::cout << "  Next hop: " << ipv4_to_string(*next_hop) << '\n';
        } else {
            std::cout << "  Routing: No matching route\n";
        }
    }

    // Print final processing statistics.
    std::cout << "\n=== Pipeline Summary ===\n";
    std::cout << "Packets processed: " << packet_number << '\n';
    std::cout << "Allowed:           " << allowed_count << '\n';
    std::cout << "Denied:            " << denied_count << '\n';
    std::cout << "Routed:             " << routed_count << '\n';
    std::cout << "Invalid/unsupported: " << invalid_count << '\n';

    return 0;
}
