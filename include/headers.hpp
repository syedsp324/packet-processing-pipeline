#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

struct IPv4Header {
    std::uint8_t ihl_bytes{}, protocol{}, ttl{};
    std::uint16_t total_length{}, fragment_offset{};
    bool more_fragments{};
    std::uint32_t src{}, dst{}; // host-order numeric values; print high byte first
    std::size_t transport_offset{};
};
struct FiveTuple {
    std::uint32_t src_ip{}, dst_ip{};
    std::uint16_t src_port{}, dst_port{};
    std::uint8_t protocol{};
    bool operator==(const FiveTuple& o) const noexcept {
        return src_ip==o.src_ip && dst_ip==o.dst_ip && src_port==o.src_port && dst_port==o.dst_port && protocol==o.protocol;
    }
};
std::optional<IPv4Header> parse_ipv4_frame(const std::uint8_t* data, std::size_t len);
std::optional<FiveTuple> extract_five_tuple(const std::uint8_t* data, std::size_t len);
std::string ipv4_to_string(std::uint32_t ip);
