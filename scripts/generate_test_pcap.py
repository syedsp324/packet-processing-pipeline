
import struct
from pathlib import Path

# Build a basic Ethernet + IPv4 + UDP packet.
def make_packet(src_ip, dst_ip, src_port, dst_port):
    src = bytes(map(int, src_ip.split(".")))
    dst = bytes(map(int, dst_ip.split(".")))

    # Ethernet header: destination MAC, source MAC, IPv4 type.
    ethernet = bytes.fromhex("aabbccddeeff1122334455660800")

    # IPv4 header: version/IHL, length, ID, flags, TTL, UDP, checksum, IPs.
    udp_length = 8
    ip_length = 20 + udp_length
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_length, 1, 0, 64, 17, 0, src, dst
    )

    # UDP header: source port, destination port, length, checksum.
    udp = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)

    return ethernet + ip_header + udp


packets = [
    make_packet("192.168.1.10", "192.168.1.20", 12345, 53),
    make_packet("10.0.0.2", "8.8.8.8", 54321, 443),
]

# Write a classic little-endian PCAP file with Ethernet link type.
output = Path("data/traces/test.pcap")
output.parent.mkdir(parents=True, exist_ok=True)

with output.open("wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    for i, packet in enumerate(packets):
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(packet), len(packet)))
        f.write(packet)

print(f"Created {output} with {len(packets)} packets.")
