#include "netprobe/parser/transport_parser.hpp"
#include <algorithm>

namespace netprobe::parser {

std::optional<model::TcpSegment> TransportParser::parse_tcp(core::ByteSpan raw_bytes) noexcept {
    if (raw_bytes.size() < model::TcpSegment::MinimumHeaderSize) {
        return std::nullopt;
    }

    uint16_t src_port = (static_cast<uint16_t>(raw_bytes[0]) << 8) |
                         static_cast<uint16_t>(raw_bytes[1]);
    uint16_t dst_port = (static_cast<uint16_t>(raw_bytes[2]) << 8) |
                         static_cast<uint16_t>(raw_bytes[3]);

    uint32_t seq_num = (static_cast<uint32_t>(raw_bytes[4]) << 24) |
                       (static_cast<uint32_t>(raw_bytes[5]) << 16) |
                       (static_cast<uint32_t>(raw_bytes[6]) << 8)  |
                        static_cast<uint32_t>(raw_bytes[7]);

    uint32_t ack_num = (static_cast<uint32_t>(raw_bytes[8]) << 24) |
                       (static_cast<uint32_t>(raw_bytes[9]) << 16) |
                       (static_cast<uint32_t>(raw_bytes[10]) << 8) |
                        static_cast<uint32_t>(raw_bytes[11]);

    uint8_t data_offset = (raw_bytes[12] >> 4) & 0x0F;
    if (data_offset < 5) {
        return std::nullopt;
    }

    size_t header_len = static_cast<size_t>(data_offset) * 4;
    if (raw_bytes.size() < header_len) {
        return std::nullopt;
    }

    uint8_t flags_byte = raw_bytes[13];
    model::TcpFlags flags{
        .fin = (flags_byte & 0x01) != 0,
        .syn = (flags_byte & 0x02) != 0,
        .rst = (flags_byte & 0x04) != 0,
        .psh = (flags_byte & 0x08) != 0,
        .ack = (flags_byte & 0x10) != 0,
        .urg = (flags_byte & 0x20) != 0,
        .ece = (flags_byte & 0x40) != 0,
        .cwr = (flags_byte & 0x80) != 0
    };

    uint16_t window_size = (static_cast<uint16_t>(raw_bytes[14]) << 8) |
                            static_cast<uint16_t>(raw_bytes[15]);
    uint16_t checksum = (static_cast<uint16_t>(raw_bytes[16]) << 8) |
                         static_cast<uint16_t>(raw_bytes[17]);
    uint16_t urgent_ptr = (static_cast<uint16_t>(raw_bytes[18]) << 8) |
                           static_cast<uint16_t>(raw_bytes[19]);

    core::ByteBuffer options;
    if (data_offset > 5) {
        size_t options_size = header_len - model::TcpSegment::MinimumHeaderSize;
        options.assign(raw_bytes.begin() + 20, raw_bytes.begin() + 20 + options_size);
    }

    core::ByteBuffer payload;
    if (raw_bytes.size() > header_len) {
        payload.assign(raw_bytes.begin() + header_len, raw_bytes.end());
    }

    return model::TcpSegment(src_port, dst_port, seq_num, ack_num, data_offset,
                            flags, window_size, checksum, urgent_ptr,
                            std::move(options), std::move(payload));
}

std::optional<model::UdpDatagram> TransportParser::parse_udp(core::ByteSpan raw_bytes) noexcept {
    if (raw_bytes.size() < model::UdpDatagram::HeaderSize) {
        return std::nullopt;
    }

    uint16_t src_port = (static_cast<uint16_t>(raw_bytes[0]) << 8) |
                         static_cast<uint16_t>(raw_bytes[1]);
    uint16_t dst_port = (static_cast<uint16_t>(raw_bytes[2]) << 8) |
                         static_cast<uint16_t>(raw_bytes[3]);
    uint16_t length = (static_cast<uint16_t>(raw_bytes[4]) << 8) |
                       static_cast<uint16_t>(raw_bytes[5]);
    uint16_t checksum = (static_cast<uint16_t>(raw_bytes[6]) << 8) |
                         static_cast<uint16_t>(raw_bytes[7]);

    if (length < model::UdpDatagram::HeaderSize) {
        return std::nullopt;
    }

    size_t payload_end = std::min(raw_bytes.size(), static_cast<size_t>(length));
    core::ByteBuffer payload;
    if (payload_end > model::UdpDatagram::HeaderSize) {
        payload.assign(raw_bytes.begin() + model::UdpDatagram::HeaderSize, raw_bytes.begin() + payload_end);
    }

    return model::UdpDatagram(src_port, dst_port, length, checksum, std::move(payload));
}

std::optional<model::IcmpPacket> TransportParser::parse_icmp(core::ByteSpan raw_bytes) noexcept {
    if (raw_bytes.size() < model::IcmpPacket::HeaderSize) {
        return std::nullopt;
    }

    uint8_t type = raw_bytes[0];
    uint8_t code = raw_bytes[1];
    uint16_t checksum = (static_cast<uint16_t>(raw_bytes[2]) << 8) |
                         static_cast<uint16_t>(raw_bytes[3]);
    uint32_t rest_of_header = (static_cast<uint32_t>(raw_bytes[4]) << 24) |
                              (static_cast<uint32_t>(raw_bytes[5]) << 16) |
                              (static_cast<uint32_t>(raw_bytes[6]) << 8)  |
                               static_cast<uint32_t>(raw_bytes[7]);

    core::ByteBuffer payload;
    if (raw_bytes.size() > model::IcmpPacket::HeaderSize) {
        payload.assign(raw_bytes.begin() + model::IcmpPacket::HeaderSize, raw_bytes.end());
    }

    return model::IcmpPacket(type, code, checksum, rest_of_header, std::move(payload));
}

}
