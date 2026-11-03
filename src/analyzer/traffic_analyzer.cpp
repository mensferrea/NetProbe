#include "netprobe/analyzer/traffic_analyzer.hpp"
#include <algorithm>

namespace netprobe::analyzer {

TrafficAnalyzer::TrafficAnalyzer()
    : start_time_(std::chrono::system_clock::now()),
      last_packet_time_(start_time_) {}

void TrafficAnalyzer::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    start_time_ = std::chrono::system_clock::now();
    last_packet_time_ = start_time_;

    total_packets_ = 0;
    total_bytes_ = 0;
    ipv4_packets_ = 0;
    ipv4_bytes_ = 0;
    arp_packets_ = 0;
    arp_bytes_ = 0;
    ipv6_packets_ = 0;
    ipv6_bytes_ = 0;
    tcp_packets_ = 0;
    tcp_bytes_ = 0;
    udp_packets_ = 0;
    udp_bytes_ = 0;
    icmp_packets_ = 0;
    icmp_bytes_ = 0;
    other_packets_ = 0;
    other_bytes_ = 0;
    invalid_packets_ = 0;

    host_stats_.clear();
    flow_stats_.clear();
}

void TrafficAnalyzer::process_packet(const model::ParsedPacket& packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    last_packet_time_ = packet.timestamp();
    size_t length = packet.original_length();

    total_packets_++;
    total_bytes_ += length;

    if (!packet.validation().is_valid) {
        invalid_packets_++;
    }

    switch (packet.ethernet().ether_type()) {
        case model::EtherType::IPv4:
            ipv4_packets_++;
            ipv4_bytes_ += length;
            break;
        case model::EtherType::ARP:
            arp_packets_++;
            arp_bytes_ += length;
            break;
        case model::EtherType::IPv6:
            ipv6_packets_++;
            ipv6_bytes_ += length;
            break;
        default:
            other_packets_++;
            other_bytes_ += length;
            break;
    }

    if (packet.has_ipv4()) {
        const auto& ip = *packet.ip();

        auto& src_host = host_stats_[ip.source()];
        src_host.sent_packets++;
        src_host.sent_bytes += length;

        auto& dst_host = host_stats_[ip.destination()];
        dst_host.recv_packets++;
        dst_host.recv_bytes += length;

        model::FlowKey flow_key{
            .src_ip = ip.source(),
            .dst_ip = ip.destination(),
            .src_port = 0,
            .dst_port = 0,
            .protocol = ip.protocol()
        };

        if (packet.has_tcp()) {
            tcp_packets_++;
            tcp_bytes_ += length;
            flow_key.src_port = packet.tcp()->source_port();
            flow_key.dst_port = packet.tcp()->destination_port();
        } else if (packet.has_udp()) {
            udp_packets_++;
            udp_bytes_ += length;
            flow_key.src_port = packet.udp()->source_port();
            flow_key.dst_port = packet.udp()->destination_port();
        } else if (packet.has_icmp()) {
            icmp_packets_++;
            icmp_bytes_ += length;
        }

        auto& flow = flow_stats_[flow_key];
        if (flow.packets == 0) {
            flow.first_seen = packet.timestamp();
        }
        flow.last_seen = packet.timestamp();
        flow.packets++;
        flow.bytes += length;
    }
}

model::TrafficSnapshot TrafficAnalyzer::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    model::TrafficSnapshot snap;

    snap.total_packets = total_packets_;
    snap.total_bytes = total_bytes_;
    snap.ipv4_packets = ipv4_packets_;
    snap.ipv4_bytes = ipv4_bytes_;
    snap.arp_packets = arp_packets_;
    snap.arp_bytes = arp_bytes_;
    snap.ipv6_packets = ipv6_packets_;
    snap.ipv6_bytes = ipv6_bytes_;
    snap.tcp_packets = tcp_packets_;
    snap.tcp_bytes = tcp_bytes_;
    snap.udp_packets = udp_packets_;
    snap.udp_bytes = udp_bytes_;
    snap.icmp_packets = icmp_packets_;
    snap.icmp_bytes = icmp_bytes_;
    snap.other_packets = other_packets_;
    snap.other_bytes = other_bytes_;
    snap.invalid_packets = invalid_packets_;

    auto now = std::chrono::system_clock::now();
    std::chrono::duration<double> duration = now - start_time_;
    snap.duration_seconds = std::max(0.001, duration.count());

    snap.packets_per_second = static_cast<double>(snap.total_packets) / snap.duration_seconds;
    snap.bytes_per_second = static_cast<double>(snap.total_bytes) / snap.duration_seconds;
    snap.megabits_per_second = (snap.bytes_per_second * 8.0) / 1'000'000.0;

    snap.top_hosts = host_stats_;

    return snap;
}

std::vector<std::pair<model::FlowKey, model::FlowStats>> TrafficAnalyzer::active_flows() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<model::FlowKey, model::FlowStats>> flows(flow_stats_.begin(), flow_stats_.end());
    std::sort(flows.begin(), flows.end(), [](const auto& a, const auto& b) {
        return a.second.bytes > b.second.bytes;
    });
    return flows;
}

}
