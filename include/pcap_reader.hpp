
#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

struct PcapPacket {
    std::uint32_t timestamp_seconds{};
    std::uint32_t timestamp_fraction{};
    std::uint32_t original_length{};
    std::vector<std::uint8_t> data;
};

class PcapReader {
public:
    explicit PcapReader(const std::string& filename);

    bool is_open() const;
    bool next(PcapPacket& packet);

private:
    std::ifstream file_;
    bool swapped_byte_order_{false};
};
