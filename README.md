
# Packet Processing Pipeline

A C++17 packet-processing pipeline that reads packet captures (PCAP), parses Ethernet and IPv4 headers, extracts TCP/UDP flow information, applies access control rules, and performs IPv4 longest-prefix-match (LPM) routing.

## Features

- **PCAP Reader:** Reads classic PCAP files with packet timestamps, captured data, and original packet lengths.
- **Packet Parsing:** Parses Ethernet II and IPv4 headers and extracts TCP/UDP five-tuples.
- **Linear Routing:** Performs IPv4 longest-prefix-match lookup using a route table.
- **Trie Routing:** Performs LPM lookup using a binary prefix trie.
- **ACL Firewall:** Evaluates ordered rules using source/destination IP masks, protocol, and destination port. Unmatched traffic is denied.
- **Integrated Pipeline:** Processes captured packets through parsing, firewall evaluation, and routing.
- **Benchmark:** Compares linear and trie routing lookup performance.

## Technology

- C++17
- CMake
- MSVC / Visual Studio
- Standard C++ library

## Project Structure

```text
packet-processing-pipeline/
├── include/
│   ├── acl.hpp
│   ├── headers.hpp
│   ├── pcap_reader.hpp
│   └── routing_table.hpp
├── src/
│   ├── acl.cpp
│   ├── headers.cpp
│   ├── main.cpp
│   ├── pcap_reader.cpp
│   └── routing_table.cpp
├── tests/
│   ├── benchmark_routing.cpp
│   ├── test_acl.cpp
│   ├── test_headers.cpp
│   ├── test_pcap_reader.cpp
│   ├── test_pipeline.cpp
│   └── test_routing.cpp
├── data/
│   ├── routes.txt
│   ├── routes_large.txt
│   └── traces/
└── CMakeLists.txt
```

## Build

Requirements: CMake and a Visual Studio C++ build environment.

From the project root, configure and build:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

## Run the Pipeline

The current executable reads the configured capture file:

```powershell
.\build\Release\packet_pipeline.exe
```

The capture path is currently hardcoded in `src/main.cpp` as `data/traces/dns.cap`. Ensure this file exists relative to the project root.

The pipeline prints packet information, firewall decisions, next hops for allowed packets, and a final summary.

## Tests

Run the test executables from the project root:

```powershell
.\build\Release\test_headers.exe
.\build\Release\test_pcap_reader.exe
.\build\Release\test_acl.exe
.\build\Release\test_routing.exe
.\build\Release\test_pipeline.exe
```

Verified results:

- Header tests: valid IPv4/UDP frame and truncated-frame rejection passed.
- PCAP reader tests: file opening, packet fields/payload, and end-of-file handling passed.
- ACL tests: four rule and default-deny checks passed.
- Routing tests: 10,000 random destination comparisons between linear and trie lookup passed.
- Pipeline integration test: parsing, UDP tuple extraction, firewall allow decision, and route lookup passed.

## Routing Benchmark

Benchmark configuration:

- Route table: `data/routes_large.txt` (10,000 routes).
- Workload: 1,000,000 randomly generated destination IP lookups.
- Both implementations used the same destinations.
- Lookup results were checked for equality before timing.
- Route loading was excluded from the timed sections.
- Build configuration: Release.

Recorded result from one run:

| Implementation | Lookup time |
|---|---:|
| Linear LPM | 10,948.7 ms |
| Binary trie LPM | 81.9379 ms |

Measured speedup: **133.62×** for the trie on this workload.

Benchmark results depend on the machine, compiler, route distribution, and destination workload. This is a measured result, not a universal performance guarantee.

To rerun the benchmark:

```powershell
.\build\Release\benchmark_routing.exe
```

## Current Limitations

- The packet reader targets classic PCAP with Ethernet link-layer frames; PCAPNG and other link types are not established as supported.
- Header parsing currently focuses on untagged Ethernet II IPv4 packets.
- The ACL is stateless and matches destination ports, not source ports or connection state.
- The current sample capture contains DNS/UDP traffic; broader TCP and protocol coverage requires additional test captures.
- The benchmark measures routing lookup performance, not end-to-end packet-processing throughput.

## Future Work

- Expand malformed-packet and protocol test coverage.
- Add more representative packet captures for validation.
- Measure end-to-end processing throughput and latency.
