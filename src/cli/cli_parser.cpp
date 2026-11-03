#include "netprobe/cli/cli_parser.hpp"
#include <iostream>
#include <cstring>

namespace netprobe::cli {

void CommandLineParser::print_usage(const char* program_name) {
    std::cout << "NetProbe — Network Packet Analyzer & Diagnostic Tool\n\n"
              << "Usage:\n"
              << "  " << program_name << " capture [options]\n"
              << "  " << program_name << " ping <destination_ip> [options]\n"
              << "  " << program_name << " stats [options]\n\n"
              << "Commands:\n"
              << "  capture                  Capture and dissect packets in real-time\n"
              << "  ping <ip>                Send ICMP Echo requests and measure RTT\n"
              << "  stats                    Analyze bandwidth, protocols, and host matrix\n\n"
              << "Options for capture & stats:\n"
              << "  -i, --interface <name>   Network interface (e.g. eth0, any)\n"
              << "  -c, --count <num>        Number of packets to capture before exiting\n"
              << "  -f, --filter <expr>      Packet filter expression (e.g. 'tcp port 80', 'src 192.168.1.1')\n"
              << "  -x, --hex                Show hex dump of captured packets\n"
              << "  -v, --verbose            Show detailed protocol header breakdown\n\n"
              << "Options for ping:\n"
              << "  -c, --count <num>        Number of ICMP requests to send (default: 4)\n"
              << "  -s, --size <bytes>       Payload size in bytes (default: 56)\n"
              << "  -W, --timeout <ms>       Timeout per packet in milliseconds (default: 2000)\n"
              << "  -i, --interval <ms>      Wait interval between pings in ms (default: 1000)\n\n";
}

std::optional<CliOptions> CommandLineParser::parse(int argc, const char* const argv[]) {
    if (argc < 2) {
        return CliOptions{.command = CommandType::Help};
    }

    CliOptions opt;
    std::string cmd = argv[1];

    if (cmd == "capture") {
        opt.command = CommandType::Capture;
    } else if (cmd == "ping") {
        opt.command = CommandType::Ping;
        if (argc < 3) {
            std::cerr << "Error: 'ping' requires destination IP address\n";
            return std::nullopt;
        }
        opt.ping_target = argv[2];
    } else if (cmd == "stats") {
        opt.command = CommandType::Stats;
    } else if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        opt.command = CommandType::Help;
        return opt;
    } else {
        std::cerr << "Error: Unknown command '" << cmd << "'\n";
        return std::nullopt;
    }

    int start_arg = (opt.command == CommandType::Ping) ? 3 : 2;

    for (int i = start_arg; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) {
                opt.interface_name = argv[++i];
            } else {
                std::cerr << "Error: Missing argument for " << arg << "\n";
                return std::nullopt;
            }
        } else if (arg == "-c" || arg == "--count") {
            if (i + 1 < argc) {
                size_t val = std::stoul(argv[++i]);
                if (opt.command == CommandType::Ping) {
                    opt.ping_count = val;
                } else {
                    opt.packet_limit = val;
                }
            } else {
                std::cerr << "Error: Missing argument for " << arg << "\n";
                return std::nullopt;
            }
        } else if (arg == "-f" || arg == "--filter") {
            if (i + 1 < argc) {
                opt.filter_expression = argv[++i];
                auto parsed_filter = filter::PacketFilter::parse_expression(opt.filter_expression);
                if (!parsed_filter) {
                    std::cerr << "Error: Invalid filter expression '" << opt.filter_expression << "'\n";
                    return std::nullopt;
                }
                opt.filter = *parsed_filter;
            } else {
                std::cerr << "Error: Missing argument for " << arg << "\n";
                return std::nullopt;
            }
        } else if (arg == "-x" || arg == "--hex") {
            opt.hex_dump = true;
        } else if (arg == "-v" || arg == "--verbose") {
            opt.verbose = true;
        } else if (arg == "-s" || arg == "--size") {
            if (i + 1 < argc) {
                opt.ping_payload_size = std::stoul(argv[++i]);
            }
        } else if (arg == "-W" || arg == "--timeout") {
            if (i + 1 < argc) {
                opt.ping_timeout_ms = static_cast<uint32_t>(std::stoul(argv[++i]));
            }
        } else if (arg == "--interval") {
            if (i + 1 < argc) {
                opt.ping_interval_ms = static_cast<uint32_t>(std::stoul(argv[++i]));
            }
        }
    }

    return opt;
}

}
