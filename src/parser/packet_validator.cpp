#include "netprobe/parser/packet_validator.hpp"
#include <numeric>

namespace netprobe::parser {

uint16_t PacketValidator::calculate_checksum(core::ByteSpan data) noexcept {
    uint32_t sum = 0;
    size_t i = 0;

    while (i + 1 < data.size()) {
        uint16_t word = (static_cast<uint16_t>(data[i]) << 8) | static_cast<uint16_t>(data[i + 1]);
        sum += word;
        i += 2;
    }

    if (i < data.size()) {
        sum += (static_cast<uint16_t>(data[i]) << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

bool PacketValidator::verify_ipv4_checksum(core::ByteSpan ip_header) noexcept {
    if (ip_header.size() < 20) {
        return false;
    }

    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < ip_header.size(); i += 2) {
        uint16_t word = (static_cast<uint16_t>(ip_header[i]) << 8) | static_cast<uint16_t>(ip_header[i + 1]);
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(sum) == 0xFFFF;
}

bool PacketValidator::verify_tcp_checksum(const model::IPv4Address& src,
                                          const model::IPv4Address& dst,
                                          core::ByteSpan tcp_raw_segment) noexcept {
    if (tcp_raw_segment.size() < 20) {
        return false;
    }

    uint32_t sum = 0;

    sum += (src.to_uint32() >> 16) & 0xFFFF;
    sum += src.to_uint32() & 0xFFFF;

    sum += (dst.to_uint32() >> 16) & 0xFFFF;
    sum += dst.to_uint32() & 0xFFFF;

    sum += static_cast<uint16_t>(model::IPProtocol::TCP);
    sum += static_cast<uint16_t>(tcp_raw_segment.size());

    size_t i = 0;
    while (i + 1 < tcp_raw_segment.size()) {
        uint16_t word = (static_cast<uint16_t>(tcp_raw_segment[i]) << 8) |
                         static_cast<uint16_t>(tcp_raw_segment[i + 1]);
        sum += word;
        i += 2;
    }

    if (i < tcp_raw_segment.size()) {
        sum += (static_cast<uint16_t>(tcp_raw_segment[i]) << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(sum) == 0xFFFF;
}

bool PacketValidator::verify_udp_checksum(const model::IPv4Address& src,
                                          const model::IPv4Address& dst,
                                          core::ByteSpan udp_raw_datagram) noexcept {
    if (udp_raw_datagram.size() < 8) {
        return false;
    }

    uint16_t checksum_field = (static_cast<uint16_t>(udp_raw_datagram[6]) << 8) |
                               static_cast<uint16_t>(udp_raw_datagram[7]);
    if (checksum_field == 0x0000) {
        return true;
    }

    uint32_t sum = 0;

    sum += (src.to_uint32() >> 16) & 0xFFFF;
    sum += src.to_uint32() & 0xFFFF;

    sum += (dst.to_uint32() >> 16) & 0xFFFF;
    sum += dst.to_uint32() & 0xFFFF;

    sum += static_cast<uint16_t>(model::IPProtocol::UDP);
    sum += static_cast<uint16_t>(udp_raw_datagram.size());

    size_t i = 0;
    while (i + 1 < udp_raw_datagram.size()) {
        uint16_t word = (static_cast<uint16_t>(udp_raw_datagram[i]) << 8) |
                         static_cast<uint16_t>(udp_raw_datagram[i + 1]);
        sum += word;
        i += 2;
    }

    if (i < udp_raw_datagram.size()) {
        sum += (static_cast<uint16_t>(udp_raw_datagram[i]) << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(sum) == 0xFFFF;
}

bool PacketValidator::verify_icmp_checksum(core::ByteSpan icmp_raw_packet) noexcept {
    if (icmp_raw_packet.size() < 4) {
        return false;
    }

    uint32_t sum = 0;
    size_t i = 0;
    while (i + 1 < icmp_raw_packet.size()) {
        uint16_t word = (static_cast<uint16_t>(icmp_raw_packet[i]) << 8) |
                         static_cast<uint16_t>(icmp_raw_packet[i + 1]);
        sum += word;
        i += 2;
    }

    if (i < icmp_raw_packet.size()) {
        sum += (static_cast<uint16_t>(icmp_raw_packet[i]) << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(sum) == 0xFFFF;
}

model::ValidationStatus PacketValidator::validate(const model::ParsedPacket& packet,
                                                  core::ByteSpan raw_frame) noexcept {
    model::ValidationStatus status;

    if (!packet.has_ipv4()) {
        return status;
    }

    const auto& ip = *packet.ip();
    size_t eth_header_len = packet.ethernet().vlan_id().has_value()
                                ? model::EthernetFrame::VlanHeaderSize
                                : model::EthernetFrame::HeaderSize;

    if (raw_frame.size() < eth_header_len + ip.header_size()) {
        status.is_valid = false;
        status.length_valid = false;
        status.error_message = "Truncated IP header";
        return status;
    }

    core::ByteSpan ip_header(raw_frame.data() + eth_header_len, ip.header_size());
    status.ip_checksum_valid = verify_ipv4_checksum(ip_header);
    if (!status.ip_checksum_valid) {
        status.is_valid = false;
        status.error_message = "Invalid IPv4 checksum";
    }

    if (packet.original_length() < eth_header_len + ip.total_length()) {
        status.length_valid = false;
        status.is_valid = false;
        if (status.error_message.empty()) {
            status.error_message = "Frame shorter than IPv4 total length";
        }
    }

    size_t transport_offset = eth_header_len + ip.header_size();
    if (transport_offset < raw_frame.size()) {
        core::ByteSpan transport_bytes(raw_frame.data() + transport_offset, raw_frame.size() - transport_offset);

        if (packet.has_tcp()) {
            status.transport_checksum_valid = verify_tcp_checksum(ip.source(), ip.destination(), transport_bytes);
            if (!status.transport_checksum_valid) {
                status.is_valid = false;
                if (status.error_message.empty()) {
                    status.error_message = "Invalid TCP checksum";
                }
            }
        } else if (packet.has_udp()) {
            status.transport_checksum_valid = verify_udp_checksum(ip.source(), ip.destination(), transport_bytes);
            if (!status.transport_checksum_valid) {
                status.is_valid = false;
                if (status.error_message.empty()) {
                    status.error_message = "Invalid UDP checksum";
                }
            }
        } else if (packet.has_icmp()) {
            status.transport_checksum_valid = verify_icmp_checksum(transport_bytes);
            if (!status.transport_checksum_valid) {
                status.is_valid = false;
                if (status.error_message.empty()) {
                    status.error_message = "Invalid ICMP checksum";
                }
            }
        }
    }

    return status;
}

}
