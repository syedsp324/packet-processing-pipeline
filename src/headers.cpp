
#include "headers.hpp"

#include <sstream>
#include <iomanip>

// Parse an Ethernet frame's IPv4 header.
std::optional<IPv4Header> parse_ipv4_frame(
    const std::uint8_t* data, std::size_t len) {

    // Need 14 bytes for Ethernet and at least 20 for IPv4.
    if (data == nullptr || len < 14 + 20)
        return std::nullopt;

    // EtherType 0x0800 identifies IPv4.
    if (data[12] != 0x08 || data[13] != 0x00)
        return std::nullopt;

    const std::size_t ip_offset = 14;
    const std::uint8_t version_ihl = data[ip_offset];
    const std::uint8_t version = version_ihl >> 4;
    const std::uint8_t ihl_bytes = (version_ihl & 0x0F) * 4;

    // Validate IPv4 version and header length.
    if (version != 4 || ihl_bytes < 20 ||
        len < ip_offset + ihl_bytes)
        return std::nullopt;

    const std::uint16_t total_length =
        (std::uint16_t(data[ip_offset + 2]) << 8) |
         std::uint16_t(data[ip_offset + 3]);

    // Reject truncated or invalid IPv4 packets.
    if (total_length < ihl_bytes ||
        len < ip_offset + total_length)
        return std::nullopt;

    const std::uint16_t flags_offset =
        (std::uint16_t(data[ip_offset + 6]) << 8) |
         std::uint16_t(data[ip_offset + 7]);

    IPv4Header header{};
    header.ihl_bytes = ihl_bytes;
    header.total_length = total_length;
    header.ttl = data[ip_offset + 8];
    header.protocol = data[ip_offset + 9];

    // Store IPv4 addresses in host-order numeric form.
    header.src =
        (std::uint32_t(data[ip_offset + 12]) << 24) |
        (std::uint32_t(data[ip_offset + 13]) << 16) |
        (std::uint32_t(data[ip_offset + 14]) << 8) |
         std::uint32_t(data[ip_offset + 15]);

    header.dst =
        (std::uint32_t(data[ip_offset + 16]) << 24) |
        (std::uint32_t(data[ip_offset + 17]) << 16) |
        (std::uint32_t(data[ip_offset + 18]) << 8) |
         std::uint32_t(data[ip_offset + 19]);

    header.fragment_offset = flags_offset & 0x1FFF;
    header.more_fragments = (flags_offset & 0x2000) != 0;
    header.transport_offset = ip_offset + ihl_bytes;

    return header;
}

// Convert a numeric IPv4 address to dotted-decimal text.
std::string ipv4_to_string(std::uint32_t ip) {
    std::ostringstream out;
    out << ((ip >> 24) & 0xFF) << '.'
        << ((ip >> 16) & 0xFF) << '.'
        << ((ip >> 8) & 0xFF) << '.'
        << (ip & 0xFF);
    return out.str();
}

// Extract the five-tuple for TCP or UDP packets.
std::optional<FiveTuple> extract_five_tuple(
    const std::uint8_t* data, std::size_t len) {

    auto ip = parse_ipv4_frame(data, len);
    if (!ip || (ip->protocol != 6 && ip->protocol != 17))
        return std::nullopt;

    // Non-initial fragments don't contain transport ports.
    if (ip->fragment_offset != 0)
        return std::nullopt;

    const std::size_t offset = ip->transport_offset;
    if (len < offset + 4)
        return std::nullopt;

    FiveTuple tuple{};
    tuple.src_ip = ip->src;
    tuple.dst_ip = ip->dst;
    tuple.protocol = ip->protocol;

    tuple.src_port =
        (std::uint16_t(data[offset]) << 8) | data[offset + 1];
    tuple.dst_port =
        (std::uint16_t(data[offset + 2]) << 8) | data[offset + 3];

    return tuple;
}
