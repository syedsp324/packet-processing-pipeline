
#include "pcap_reader.hpp"

#include <array>
#include <stdexcept>

// Read a 32-bit value using the file's byte order.
static std::uint32_t read_u32(
    const std::uint8_t* p, bool swapped) {
    if (swapped) {
        return (std::uint32_t(p[0]) << 24) |
               (std::uint32_t(p[1]) << 16) |
               (std::uint32_t(p[2]) << 8)  |
                std::uint32_t(p[3]);
    }

    return (std::uint32_t(p[3]) << 24) |
           (std::uint32_t(p[2]) << 16) |
           (std::uint32_t(p[1]) << 8)  |
            std::uint32_t(p[0]);
}

PcapReader::PcapReader(const std::string& filename)
    : file_(filename, std::ios::binary) {
    if (!file_) return;

    // Read the 24-byte classic PCAP global header.
    std::array<std::uint8_t, 24> header{};
    file_.read(reinterpret_cast<char*>(header.data()), header.size());

    if (!file_) {
        file_.setstate(std::ios::failbit);
        return;
    }

    // Detect classic PCAP byte order and timestamp precision.
    const std::array<std::uint8_t, 4> magic = {
        header[0], header[1], header[2], header[3]
    };

    const bool little_micro =
        magic == std::array<std::uint8_t, 4>{0xd4, 0xc3, 0xb2, 0xa1};
    const bool big_micro =
        magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0xc3, 0xd4};
    const bool little_nano =
        magic == std::array<std::uint8_t, 4>{0x4d, 0x3c, 0xb2, 0xa1};
    const bool big_nano =
        magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0x3c, 0x4d};

    if (!little_micro && !big_micro && !little_nano && !big_nano) {
        file_.setstate(std::ios::failbit);
        return;
    }

    swapped_byte_order_ = big_micro || big_nano;

    // Validate PCAP version 2.4 and Ethernet link type.
    const auto version = read_u32(header.data() + 4, swapped_byte_order_);
    const auto link_type = read_u32(header.data() + 20, swapped_byte_order_);

        if ((version & 0xFFFF) != 2 ||
            (version >> 16) != 4 ||
            link_type != 1) {
            file_.setstate(std::ios::failbit);
        }
}

bool PcapReader::is_open() const {
    return file_.is_open() && !file_.fail();
}

bool PcapReader::next(PcapPacket& packet) {
    if (!file_) return false;

    // Read the 16-byte packet record header.
    std::array<std::uint8_t, 16> record{};
    file_.read(reinterpret_cast<char*>(record.data()), record.size());

    if (file_.gcount() == 0 && file_.eof()) return false;
    if (file_.gcount() != static_cast<std::streamsize>(record.size())) {
        file_.setstate(std::ios::failbit);
        return false;
    }

    const auto captured_length =
        read_u32(record.data() + 8, swapped_byte_order_);

    packet.timestamp_seconds =
        read_u32(record.data(), swapped_byte_order_);
    packet.timestamp_fraction =
        read_u32(record.data() + 4, swapped_byte_order_);
    packet.original_length =
        read_u32(record.data() + 12, swapped_byte_order_);

    // Reject unreasonable lengths before allocating memory.
    constexpr std::uint32_t MAX_PACKET_SIZE = 16 * 1024 * 1024;
    if (captured_length > MAX_PACKET_SIZE ||
        captured_length > packet.original_length) {
        file_.setstate(std::ios::failbit);
        return false;
    }

    packet.data.resize(captured_length);
    file_.read(reinterpret_cast<char*>(packet.data.data()),
               captured_length);

    // Reject truncated packet data.
    if (file_.gcount() != static_cast<std::streamsize>(captured_length)) {
        file_.setstate(std::ios::failbit);
        return false;
    }

    return true;
}
