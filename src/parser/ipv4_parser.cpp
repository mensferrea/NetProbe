#include "netprobe/parser/ipv4_parser.hpp"
#include <algorithm>

namespace netprobe::parser {

std::optional<model::IPv4Packet> IPv4Parser::parse(core::ByteSpan raw_bytes) noexcept {
    if (raw_bytes.size() < model::IPv4Packet::MinimumHeaderSize) {
        return std::nullopt;
    }

    uint8_t ver_ihl = raw_bytes[0];
    uint8_t version = (ver_ihl >> 4) & 0x0F;
    uint8_t ihl = ver_ihl & 0x0F;

    if (version != 4 || ihl < 5) {
        return std::nullopt;
    }

    size_t header_len = static_cast<size_t>(ihl) * 4;
    if (raw_bytes.size() < header_len) {
        return std::nullopt;
    }

    uint8_t dscp_ecn = raw_bytes[1];
    uint8_t dscp = (dscp_ecn >> 2) & 0x3F;
    uint8_t ecn = dscp_ecn & 0x03;

    uint16_t total_length = (static_cast<uint16_t>(raw_bytes[2]) << 8) |
                             static_cast<uint16_t>(raw_bytes[3]);

    if (total_length < header_len) {
        return std::nullopt;
    }

    uint16_t identification = (static_cast<uint16_t>(raw_bytes[4]) << 8) |
                               static_cast<uint16_t>(raw_bytes[5]);

    uint16_t flags_frag = (static_cast<uint16_t>(raw_bytes[6]) << 8) |
                           static_cast<uint16_t>(raw_bytes[7]);

    model::IPv4Flags flags{
        .dont_fragment = (flags_frag & 0x4000) != 0,
        .more_fragments = (flags_frag & 0x2000) != 0
    };

    uint16_t fragment_offset = flags_frag & 0x1FFF;

    uint8_t ttl = raw_bytes[8];
    uint8_t proto_raw = raw_bytes[9];

    model::IPProtocol protocol = model::IPProtocol::Unknown;
    switch (proto_raw) {
        case 1:
            protocol = model::IPProtocol::ICMP;
            break;
        case 6:
            protocol = model::IPProtocol::TCP;
            break;
        case 17:
            protocol = model::IPProtocol::UDP;
            break;
        default:
            protocol = model::IPProtocol::Unknown;
            break;
    }

    uint16_t checksum = (static_cast<uint16_t>(raw_bytes[10]) << 8) |
                         static_cast<uint16_t>(raw_bytes[11]);

    model::IPv4Address src(raw_bytes[12], raw_bytes[13], raw_bytes[14], raw_bytes[15]);
    model::IPv4Address dst(raw_bytes[16], raw_bytes[17], raw_bytes[18], raw_bytes[19]);

    core::ByteBuffer options;
    if (ihl > 5) {
        size_t options_size = header_len - model::IPv4Packet::MinimumHeaderSize;
        options.assign(raw_bytes.begin() + 20, raw_bytes.begin() + 20 + options_size);
    }

    size_t payload_end = std::min(raw_bytes.size(), static_cast<size_t>(total_length));
    core::ByteBuffer payload;
    if (payload_end > header_len) {
        payload.assign(raw_bytes.begin() + header_len, raw_bytes.begin() + payload_end);
    }

    return model::IPv4Packet(version, ihl, dscp, ecn, total_length, identification,
                             flags, fragment_offset, ttl, protocol, checksum,
                             src, dst, std::move(options), std::move(payload));
}

}
