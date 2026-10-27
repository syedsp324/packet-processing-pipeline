
#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>

#include "pcap_reader.hpp"

bool create_test_pcap(const char* filename) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) return false;

    // Classic PCAP global header, little-endian, Ethernet.
    const std::uint8_t global_header[] = {
        0xD4, 0xC3, 0xB2, 0xA1,
        0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00
    };
    out.write(reinterpret_cast<const char*>(global_header),
              sizeof(global_header));

    // One packet record containing four test bytes.
    const std::uint8_t record_header[] = {
        0x01, 0x00, 0x00, 0x00, // timestamp seconds
        0x02, 0x00, 0x00, 0x00, // timestamp fraction
        0x04, 0x00, 0x00, 0x00, // captured length
        0x04, 0x00, 0x00, 0x00  // original length
    };
    const std::uint8_t payload[] = {0xAA, 0xBB, 0xCC, 0xDD};

    out.write(reinterpret_cast<const char*>(record_header),
              sizeof(record_header));
    out.write(reinterpret_cast<const char*>(payload), sizeof(payload));
    return static_cast<bool>(out);
}

int main() {
    const char* filename = "test_reader_tmp.pcap";

    if (!create_test_pcap(filename)) {
        std::cerr << "Could not create test PCAP\n";
        return 1;
    }

    PcapReader reader(filename);
    if (!reader.is_open()) {
        std::cerr << "PCAP open: FAIL\n";
        return 1;
    }

    PcapPacket packet;
    const bool read_ok = reader.next(packet);
    const bool packet_ok =
        read_ok &&
        packet.timestamp_seconds == 1 &&
        packet.timestamp_fraction == 2 &&
        packet.original_length == 4 &&
        packet.data == std::vector<std::uint8_t>({0xAA, 0xBB, 0xCC, 0xDD});

    const bool eof_ok = !reader.next(packet);

    std::remove(filename);

    std::cout << "PCAP opens: PASS\n";
    std::cout << "Packet fields and payload: "
              << (packet_ok ? "PASS" : "FAIL") << '\n';
    std::cout << "End-of-file handling: "
              << (eof_ok ? "PASS" : "FAIL") << '\n';

    if (!packet_ok || !eof_ok) return 1;

    std::cout << "PCAP reader tests: ALL PASSED\n";
    return 0;
}
