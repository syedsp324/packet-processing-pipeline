
#include <cstdint>
#include <iostream>
#include <vector>

#include "headers.hpp"

bool test_valid_ipv4_udp() {
    const std::vector<std::uint8_t> frame = {
        // Ethernet header: IPv4 EtherType
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x08, 0x00,

        // IPv4 header: 20 bytes, UDP, total length 28
        0x45, 0x00, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x0A,
        0xC0, 0xA8, 0x01, 0x14,

        // UDP header: source port 12345, destination port 53
        0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00
    };

    const auto ip = parse_ipv4_frame(frame.data(), frame.size());
    if (!ip) return false;

    if (ipv4_to_string(ip->src) != "192.168.1.10") return false;
    if (ipv4_to_string(ip->dst) != "192.168.1.20") return false;
    if (ip->protocol != 17) return false;

    const auto tuple = extract_five_tuple(frame.data(), frame.size());
    return tuple &&
           tuple->src_port == 12345 &&
           tuple->dst_port == 53 &&
           tuple->protocol == 17;
}

bool test_truncated_frame_rejected() {
    const std::vector<std::uint8_t> frame = {0x00, 0x11, 0x22};
    return !parse_ipv4_frame(frame.data(), frame.size());
}

int main() {
    const bool valid = test_valid_ipv4_udp();
    const bool truncated = test_truncated_frame_rejected();

    std::cout << "Valid IPv4/UDP frame: "
              << (valid ? "PASS" : "FAIL") << '\n';
    std::cout << "Truncated frame rejected: "
              << (truncated ? "PASS" : "FAIL") << '\n';

    if (!valid || !truncated) return 1;

    std::cout << "Header tests: ALL PASSED\n";
    return 0;
}
