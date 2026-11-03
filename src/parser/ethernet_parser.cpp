#include "netprobe/parser/ethernet_parser.hpp"
#include "netprobe/core/byte_order.hpp"

namespace netprobe::parser {

std::optional<model::EthernetFrame> EthernetParser::parse(core::ByteSpan raw_bytes) noexcept {
    if (raw_bytes.size() < model::EthernetFrame::HeaderSize) {
        return std::nullopt;
    }

    model::MacAddress::RawBytes dst_bytes{};
    for (size_t i = 0; i < 6; ++i) {
        dst_bytes[i] = raw_bytes[i];
    }
    model::MacAddress dst(dst_bytes);

    model::MacAddress::RawBytes src_bytes{};
    for (size_t i = 0; i < 6; ++i) {
        src_bytes[i] = raw_bytes[6 + i];
    }
    model::MacAddress src(src_bytes);

    uint16_t ether_type_raw = (static_cast<uint16_t>(raw_bytes[12]) << 8) |
                               static_cast<uint16_t>(raw_bytes[13]);

    size_t payload_offset = model::EthernetFrame::HeaderSize;
    std::optional<uint16_t> vlan_id = std::nullopt;

    if (ether_type_raw == 0x8100) {
        if (raw_bytes.size() < model::EthernetFrame::VlanHeaderSize) {
            return std::nullopt;
        }

        uint16_t tci = (static_cast<uint16_t>(raw_bytes[14]) << 8) |
                        static_cast<uint16_t>(raw_bytes[15]);
        vlan_id = tci & 0x0FFF;

        ether_type_raw = (static_cast<uint16_t>(raw_bytes[16]) << 8) |
                          static_cast<uint16_t>(raw_bytes[17]);
        payload_offset = model::EthernetFrame::VlanHeaderSize;
    }

    model::EtherType ether_type = model::EtherType::Unknown;
    switch (ether_type_raw) {
        case 0x0800:
            ether_type = model::EtherType::IPv4;
            break;
        case 0x0806:
            ether_type = model::EtherType::ARP;
            break;
        case 0x86DD:
            ether_type = model::EtherType::IPv6;
            break;
        default:
            ether_type = model::EtherType::Unknown;
            break;
    }

    core::ByteBuffer payload(raw_bytes.begin() + payload_offset, raw_bytes.end());

    return model::EthernetFrame(dst, src, ether_type, std::move(payload), vlan_id);
}

}
