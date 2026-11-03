#include "netprobe/cli/cli_parser.hpp"
#include "netprobe/cli/formatter.hpp"
#include "netprobe/capture/linux_raw_socket_source.hpp"
#include "netprobe/capture/capture_engine.hpp"
#include "netprobe/analyzer/traffic_analyzer.hpp"
#include "netprobe/diagnostics/ping_service.hpp"
#include "netprobe/core/error.hpp"

#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>

namespace {
std::atomic<bool> g_stop_requested{false};

void signal_handler(int) {
    g_stop_requested.store(true);
}
}

int main(int argc, char* argv[]) {
    auto options_opt = netprobe::cli::CommandLineParser::parse(argc, argv);
    if (!options_opt) {
        return 1;
    }

    const auto& options = *options_opt;

    if (options.command == netprobe::cli::CommandType::Help) {
        netprobe::cli::CommandLineParser::print_usage(argv[0]);
        return 0;
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        if (options.command == netprobe::cli::CommandType::Ping) {
            auto target_ip = netprobe::model::IPv4Address::from_string(options.ping_target);
            if (!target_ip) {
                std::cerr << "Invalid target IPv4 address: " << options.ping_target << "\n";
                return 1;
            }

            std::cout << "NETPROBE PING " << target_ip->to_string() << " with "
                      << options.ping_payload_size << " bytes of data:\n";

            netprobe::diagnostics::LinuxPingService ping_service;
            netprobe::diagnostics::PingRequest request{
                .target_ip = *target_ip,
                .count = options.ping_count,
                .payload_size = options.ping_payload_size,
                .interval = std::chrono::milliseconds(options.ping_interval_ms),
                .timeout = std::chrono::milliseconds(options.ping_timeout_ms)
            };

            auto summary = ping_service.execute(request, [](const netprobe::diagnostics::PingResponse& resp) {
                std::cout << netprobe::cli::Formatter::format_ping_response(resp) << "\n";
            });

            std::cout << netprobe::cli::Formatter::format_ping_summary(summary);
            return 0;
        }

        auto source = std::make_shared<netprobe::capture::LinuxRawSocketSource>(options.interface_name);
        netprobe::capture::CaptureEngine engine(source);

        if (options.command == netprobe::cli::CommandType::Capture) {
            std::atomic<size_t> matched_packets{0};

            engine.add_listener([&](const netprobe::model::ParsedPacket& packet, const netprobe::core::RawPacket& raw) {
                if (options.filter.matches(packet)) {
                    matched_packets.fetch_add(1, std::memory_order_relaxed);

                    if (options.verbose) {
                        std::cout << netprobe::cli::Formatter::format_packet_detailed(packet,
                                        options.hex_dump ? raw.data : netprobe::core::ByteSpan{}) << "\n";
                    } else {
                        std::cout << netprobe::cli::Formatter::format_packet_line(packet) << "\n";
                        if (options.hex_dump) {
                            std::cout << netprobe::cli::Formatter::format_hex_dump(raw.data) << "\n";
                        }
                    }

                    if (options.packet_limit > 0 && matched_packets.load() >= options.packet_limit) {
                        g_stop_requested.store(true);
                    }
                }
            });

            std::cout << "Starting packet capture on interface '" << options.interface_name << "'...\n";
            engine.start();

            while (!g_stop_requested.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            engine.stop();
            std::cout << "\nCapture finished: " << engine.captured_packets_count()
                      << " captured, " << matched_packets.load() << " matched filter.\n";
            return 0;
        }

        if (options.command == netprobe::cli::CommandType::Stats) {
            netprobe::analyzer::TrafficAnalyzer analyzer;

            engine.add_listener([&](const netprobe::model::ParsedPacket& packet, const netprobe::core::RawPacket&) {
                if (options.filter.matches(packet)) {
                    analyzer.process_packet(packet);
                }
            });

            std::cout << "Analyzing traffic on interface '" << options.interface_name << "'...\n";
            engine.start();

            while (!g_stop_requested.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(options.stats_interval_seconds));
                auto snap = analyzer.snapshot();
                std::cout << netprobe::cli::Formatter::format_traffic_snapshot(snap);

                if (options.packet_limit > 0 && snap.total_packets >= options.packet_limit) {
                    break;
                }
            }

            engine.stop();
            return 0;
        }

    } catch (const netprobe::core::NetProbeException& ex) {
        std::cerr << "NetProbe Error: " << ex.what() << "\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "Standard Exception: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
