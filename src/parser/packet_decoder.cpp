#include "netprobe/parser/packet_decoder.hpp"
#include "netprobe/parser/ethernet_parser.hpp"
#include "netprobe/parser/ipv4_parser.hpp"
#include "netprobe/parser/transport_parser.hpp"
#include "netprobe/parser/packet_validator.hpp"

namespace netprobe::parser {

std::optional<model::ParsedPacket> PacketDecoder::decode(const core::RawPacket& raw_packet) noexcept {
    return decode(raw_packet.data, raw_packet.timestamp, raw_packet.interface_name);
}

std::optional<model::ParsedPacket> PacketDecoder::decode(core::ByteSpan bytes,
                                                         core::Timestamp timestamp,
                                                         std::string_view interface_name) noexcept {
    auto eth_opt = EthernetParser::parse(bytes);
    if (!eth_opt) {
        return std::nullopt;
    }

    std::optional<model::IPv4Packet> ip_opt = std::nullopt;
    model::TransportLayer transport = std::monostate{};

    if (eth_opt->ether_type() == model::EtherType::IPv4) {
        ip_opt = IPv4Parser::parse(eth_opt->payload());
        if (ip_opt) {
            switch (ip_opt->protocol()) {
                case model::IPProtocol::TCP: {
                    auto tcp_opt = TransportParser::parse_tcp(ip_opt->payload());
                    if (tcp_opt) {
                        transport = *tcp_opt;
                    }
                    break;
                }
                case model::IPProtocol::UDP: {
                    auto udp_opt = TransportParser::parse_udp(ip_opt->payload());
                    if (udp_opt) {
                        transport = *udp_opt;
                    }
                    break;
                }
                case model::IPProtocol::ICMP: {
                    auto icmp_opt = TransportParser::parse_icmp(ip_opt->payload());
                    if (icmp_opt) {
                        transport = *icmp_opt;
                    }
                    break;
                }
                default:
                    break;
            }
        }
    }

    model::ParsedPacket packet(timestamp, std::string(interface_name), bytes.size(),
                               *eth_opt, ip_opt, transport);

    auto status = PacketValidator::validate(packet, bytes);
    packet.set_validation(status);

    return packet;
}

}
