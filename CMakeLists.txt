cmake_minimum_required(VERSION 3.20)

project(PacketProcessingPipeline LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(packet_pipeline
    src/main.cpp
    src/pcap_reader.cpp
    src/headers.cpp
    src/routing_table.cpp
    src/acl.cpp
)
add_executable(test_acl
    tests/test_acl.cpp
    src/acl.cpp
)
add_executable(test_routing
    tests/test_routing.cpp
    src/routing_table.cpp
)

add_executable(benchmark_routing
    tests/benchmark_routing.cpp
    src/routing_table.cpp
)
add_executable(test_headers
    tests/test_headers.cpp
    src/headers.cpp
)
add_executable(test_pcap_reader
    tests/test_pcap_reader.cpp
    src/pcap_reader.cpp
)
add_executable(test_pipeline
    tests/test_pipeline.cpp
    src/headers.cpp
    src/routing_table.cpp
    src/acl.cpp
)
target_include_directories(test_pipeline PRIVATE include)
target_include_directories(test_pcap_reader PRIVATE include)
target_include_directories(test_headers PRIVATE include)
target_include_directories(benchmark_routing PRIVATE include)

target_include_directories(test_routing PRIVATE include)

target_include_directories(test_acl PRIVATE include)

target_include_directories(packet_pipeline PRIVATE include)
