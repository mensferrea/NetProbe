#include "netprobe/cli/formatter.hpp"
#include <iomanip>
#include <sstream>
#include <cctype>

namespace netprobe::cli {

std::string Formatter::format_packet_line(const model::ParsedPacket& packet) {
    std::ostringstream oss;

    auto time_c = std::chrono::system_clock::to_time_t(packet.timestamp());
    auto tm_val = *std::localtime(&time_c);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  packet.timestamp().time_since_epoch()) % 1000;

    oss << std::put_time(&tm_val, "%H:%M:%S") << "."
        << std::setfill('0') << std::setw(3) << ms.count() << " ";

    oss << "[" << packet.interface_name() << "] ";

    if (packet.has_ipv4()) {
        const auto& ip = *packet.ip();
        oss << ip.source().to_string();

        if (packet.has_tcp()) {
            oss << ":" << packet.tcp()->source_port() << " -> "
                << ip.destination().to_string() << ":" << packet.tcp()->destination_port()
                << " [TCP] [" << packet.tcp()->flags().to_string() << "] "
                << "seq " << packet.tcp()->sequence_number()
                << " ack " << packet.tcp()->ack_number()
                << " win " << packet.tcp()->window_size();
        } else if (packet.has_udp()) {
            oss << ":" << packet.udp()->source_port() << " -> "
                << ip.destination().to_string() << ":" << packet.udp()->destination_port()
                << " [UDP] len " << packet.udp()->length();
        } else if (packet.has_icmp()) {
            oss << " -> " << ip.destination().to_string()
                << " [ICMP] " << model::to_string(packet.icmp()->type())
                << " id " << packet.icmp()->identifier()
                << " seq " << packet.icmp()->sequence_number();
        } else {
            oss << " -> " << ip.destination().to_string()
                << " [IP proto " << static_cast<int>(ip.protocol()) << "]";
        }
    } else {
        oss << packet.ethernet().source().to_string() << " -> "
            << packet.ethernet().destination().to_string() << " ["
            << model::to_string(packet.ethernet().ether_type()) << "]";
    }

    oss << " (" << packet.original_length() << " bytes)";

    if (!packet.validation().is_valid) {
        oss << " [INVALID: " << packet.validation().error_message << "]";
    }

    return oss.str();
}

std::string Formatter::format_packet_detailed(const model::ParsedPacket& packet, core::ByteSpan raw_data) {
    std::ostringstream oss;
    oss << "=== Frame (" << packet.original_length() << " bytes) on " << packet.interface_name() << " ===\n";

    const auto& eth = packet.ethernet();
    oss << "Ethernet II, Src: " << eth.source().to_string()
        << ", Dst: " << eth.destination().to_string()
        << ", Type: " << model::to_string(eth.ether_type());
    if (eth.vlan_id().has_value()) {
        oss << ", VLAN ID: " << *eth.vlan_id();
    }
    oss << "\n";

    if (packet.has_ipv4()) {
        const auto& ip = *packet.ip();
        oss << "Internet Protocol Version 4, Src: " << ip.source().to_string()
            << ", Dst: " << ip.destination().to_string() << "\n"
            << "  Header Length: " << ip.header_size() << " bytes, Total Length: " << ip.total_length() << " bytes\n"
            << "  TTL: " << static_cast<int>(ip.ttl())
            << ", Protocol: " << model::to_string(ip.protocol())
            << ", Checksum: 0x" << std::hex << ip.header_checksum() << std::dec;
        if (!packet.validation().ip_checksum_valid) {
            oss << " [INCORRECT]";
        }
        oss << "\n";

        if (packet.has_tcp()) {
            const auto* tcp = packet.tcp();
            oss << "Transmission Control Protocol, Src Port: " << tcp->source_port()
                << ", Dst Port: " << tcp->destination_port() << "\n"
                << "  Seq: " << tcp->sequence_number() << ", Ack: " << tcp->ack_number() << "\n"
                << "  Flags: " << tcp->flags().to_string()
                << ", Window: " << tcp->window_size()
                << ", Checksum: 0x" << std::hex << tcp->checksum() << std::dec;
            if (!packet.validation().transport_checksum_valid) {
                oss << " [INCORRECT]";
            }
            oss << "\n  Payload Size: " << tcp->payload().size() << " bytes\n";
        } else if (packet.has_udp()) {
            const auto* udp = packet.udp();
            oss << "User Datagram Protocol, Src Port: " << udp->source_port()
                << ", Dst Port: " << udp->destination_port() << "\n"
                << "  Length: " << udp->length()
                << ", Checksum: 0x" << std::hex << udp->checksum() << std::dec << "\n"
                << "  Payload Size: " << udp->payload().size() << " bytes\n";
        } else if (packet.has_icmp()) {
            const auto* icmp = packet.icmp();
            oss << "Internet Control Message Protocol\n"
                << "  Type: " << model::to_string(icmp->type()) << " (" << static_cast<int>(icmp->type_raw()) << ")\n"
                << "  Code: " << static_cast<int>(icmp->code())
                << ", Identifier: " << icmp->identifier()
                << ", Sequence: " << icmp->sequence_number() << "\n"
                << "  Checksum: 0x" << std::hex << icmp->checksum() << std::dec << "\n";
        }
    }

    if (!raw_data.empty()) {
        oss << "\nHex Dump:\n" << format_hex_dump(raw_data);
    }

    return oss.str();
}

std::string Formatter::format_hex_dump(core::ByteSpan data) {
    std::ostringstream oss;
    size_t offset = 0;

    while (offset < data.size()) {
        oss << std::setfill('0') << std::setw(4) << std::hex << offset << "  ";

        for (size_t i = 0; i < 16; ++i) {
            if (offset + i < data.size()) {
                oss << std::setfill('0') << std::setw(2) << std::hex
                    << static_cast<unsigned int>(data[offset + i]) << " ";
            } else {
                oss << "   ";
            }
            if (i == 7) oss << " ";
        }

        oss << " |";
        for (size_t i = 0; i < 16; ++i) {
            if (offset + i < data.size()) {
                uint8_t c = data[offset + i];
                oss << (std::isprint(c) ? static_cast<char>(c) : '.');
            } else {
                break;
            }
        }
        oss << "|\n";

        offset += 16;
    }

    return oss.str();
}

std::string Formatter::format_traffic_snapshot(const model::TrafficSnapshot& snap) {
    std::ostringstream oss;
    oss << "\n================ Traffic Statistics ================\n"
        << "Duration: " << std::fixed << std::setprecision(2) << snap.duration_seconds << " s\n"
        << "Total Packets: " << snap.total_packets << " ("
        << std::setprecision(1) << snap.packets_per_second << " pkts/s)\n"
        << "Total Bytes:   " << snap.total_bytes << " ("
        << std::setprecision(3) << snap.megabits_per_second << " Mbits/s)\n"
        << "---------------- Protocol Breakdown ----------------\n"
        << "IPv4:  " << snap.ipv4_packets << " pkts, " << snap.ipv4_bytes << " bytes\n"
        << "  TCP:  " << snap.tcp_packets << " pkts, " << snap.tcp_bytes << " bytes\n"
        << "  UDP:  " << snap.udp_packets << " pkts, " << snap.udp_bytes << " bytes\n"
        << "  ICMP: " << snap.icmp_packets << " pkts, " << snap.icmp_bytes << " bytes\n"
        << "ARP:   " << snap.arp_packets << " pkts, " << snap.arp_bytes << " bytes\n"
        << "IPv6:  " << snap.ipv6_packets << " pkts, " << snap.ipv6_bytes << " bytes\n"
        << "Other: " << snap.other_packets << " pkts, " << snap.other_bytes << " bytes\n"
        << "Invalid/Corrupted: " << snap.invalid_packets << " pkts\n";

    if (!snap.top_hosts.empty()) {
        oss << "---------------- Top Active Hosts ------------------\n";
        for (const auto& [host, stats] : snap.top_hosts) {
            oss << std::left << std::setw(16) << host.to_string()
                << " Sent: " << std::setw(6) << stats.sent_packets << " pkts ("
                << std::setw(8) << stats.sent_bytes << " B), "
                << " Recv: " << std::setw(6) << stats.recv_packets << " pkts ("
                << std::setw(8) << stats.recv_bytes << " B)\n";
        }
    }
    oss << "====================================================\n";

    return oss.str();
}

std::string Formatter::format_ping_response(const diagnostics::PingResponse& resp) {
    std::ostringstream oss;
    if (resp.is_success) {
        double rtt_ms = static_cast<double>(resp.rtt.count()) / 1000.0;
        oss << resp.bytes_received << " bytes from " << resp.reply_ip.to_string()
            << ": icmp_seq=" << resp.sequence
            << " ttl=" << static_cast<int>(resp.ttl)
            << " time=" << std::fixed << std::setprecision(2) << rtt_ms << " ms";
    } else {
        oss << "icmp_seq=" << resp.sequence << ": " << resp.error_message;
    }
    return oss.str();
}

std::string Formatter::format_ping_summary(const diagnostics::PingSummary& summary) {
    std::ostringstream oss;
    oss << "\n--- " << summary.target_ip.to_string() << " ping statistics ---\n"
        << summary.packets_transmitted << " packets transmitted, "
        << summary.packets_received << " received, "
        << std::fixed << std::setprecision(1) << summary.packet_loss_percent << "% packet loss\n";

    if (summary.packets_received > 0) {
        oss << "rtt min/avg/max/mdev = "
            << std::setprecision(3) << summary.min_rtt_ms << "/"
            << summary.avg_rtt_ms << "/"
            << summary.max_rtt_ms << "/"
            << summary.mdev_rtt_ms << " ms\n";
    }

    return oss.str();
}

}
