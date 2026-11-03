cmake_minimum_required(VERSION 3.22)
project(NetProbe VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Build NetProbe GoogleTest suite" ON)

include(FetchContent)

set(NETPROBE_CORE_SOURCES
    src/model/mac_address.cpp
    src/model/ip_address.cpp
    src/model/ethernet_frame.cpp
    src/model/ipv4_packet.cpp
    src/model/tcp_segment.cpp
    src/model/icmp_packet.cpp
    src/parser/ethernet_parser.cpp
    src/parser/ipv4_parser.cpp
    src/parser/transport_parser.cpp
    src/parser/packet_validator.cpp
    src/parser/packet_decoder.cpp
    src/capture/mock_packet_source.cpp
    src/capture/linux_raw_socket_source.cpp
    src/capture/capture_engine.cpp
    src/filter/packet_filter.cpp
    src/analyzer/traffic_analyzer.cpp
    src/diagnostics/ping_service.cpp
    src/cli/formatter.cpp
    src/cli/cli_parser.cpp
)

add_library(netprobe_core STATIC ${NETPROBE_CORE_SOURCES})

target_include_directories(netprobe_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

find_package(Threads REQUIRED)
target_link_libraries(netprobe_core PUBLIC Threads::Threads)

if(WIN32)
    target_link_libraries(netprobe_core PUBLIC ws2_32)
endif()

add_executable(netprobe src/main.cpp)
target_link_libraries(netprobe PRIVATE netprobe_core)

if(BUILD_TESTS)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()
    add_executable(netprobe_tests tests/netprobe_tests.cpp)
    target_link_libraries(netprobe_tests PRIVATE netprobe_core GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(netprobe_tests)
endif()
