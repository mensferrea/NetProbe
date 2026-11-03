#include "netprobe/filter/packet_filter.hpp"
#include <sstream>
#include <charconv>

namespace netprobe::filter {

PacketFilter::PacketFilter(FilterConfig config)
    : config_(std::move(config)) {}

bool PacketFilter::matches(const model::ParsedPacket& packet) const noexcept {
    if (config_.only_valid.has_value() && *config_.only_valid && !packet.validation().is_valid) {
        return false;
    }

    if (config_.min_packet_length.has_value() && packet.original_length() < *config_.min_packet_length) {
        return false;
    }

    if (config_.max_packet_length.has_value() && packet.original_length() > *config_.max_packet_length) {
        return false;
    }

    if (config_.ether_type.has_value() && packet.ethernet().ether_type() != *config_.ether_type) {
        return false;
    }

    if (config_.source_ip || config_.destination_ip || config_.host_ip || config_.protocol) {
        if (!packet.has_ipv4()) {
            return false;
        }

        const auto& ip = *packet.ip();

        if (config_.protocol.has_value() && ip.protocol() != *config_.protocol) {
            return false;
        }

        if (config_.source_ip.has_value()) {
            if (config_.source_cidr_prefix.has_value()) {
                if (!ip.source().matches_cidr(*config_.source_ip, *config_.source_cidr_prefix)) {
                    return false;
                }
            } else if (ip.source() != *config_.source_ip) {
                return false;
            }
        }

        if (config_.destination_ip.has_value()) {
            if (config_.destination_cidr_prefix.has_value()) {
                if (!ip.destination().matches_cidr(*config_.destination_ip, *config_.destination_cidr_prefix)) {
                    return false;
                }
            } else if (ip.destination() != *config_.destination_ip) {
                return false;
            }
        }

        if (config_.host_ip.has_value()) {
            if (ip.source() != *config_.host_ip && ip.destination() != *config_.host_ip) {
                return false;
            }
        }
    }

    if (config_.source_port || config_.destination_port || config_.port || config_.tcp_syn_only) {
        uint16_t src_p = 0;
        uint16_t dst_p = 0;
        bool has_port = false;

        if (packet.has_tcp()) {
            const auto* tcp = packet.tcp();
            src_p = tcp->source_port();
            dst_p = tcp->destination_port();
            has_port = true;

            if (config_.tcp_syn_only.has_value() && *config_.tcp_syn_only) {
                if (!tcp->flags().syn || tcp->flags().ack) {
                    return false;
                }
            }
        } else if (packet.has_udp()) {
            const auto* udp = packet.udp();
            src_p = udp->source_port();
            dst_p = udp->destination_port();
            has_port = true;

            if (config_.tcp_syn_only.has_value() && *config_.tcp_syn_only) {
                return false;
            }
        } else {
            return false;
        }

        if (has_port) {
            if (config_.source_port.has_value() && src_p != *config_.source_port) {
                return false;
            }
            if (config_.destination_port.has_value() && dst_p != *config_.destination_port) {
                return false;
            }
            if (config_.port.has_value() && src_p != *config_.port && dst_p != *config_.port) {
                return false;
            }
        }
    }

    return true;
}

void PacketFilter::set_source_ip(model::IPv4Address ip, std::optional<uint8_t> cidr) {
    config_.source_ip = ip;
    config_.source_cidr_prefix = cidr;
}

void PacketFilter::set_destination_ip(model::IPv4Address ip, std::optional<uint8_t> cidr) {
    config_.destination_ip = ip;
    config_.destination_cidr_prefix = cidr;
}

void PacketFilter::set_host_ip(model::IPv4Address ip) {
    config_.host_ip = ip;
}

void PacketFilter::set_port(uint16_t port) {
    config_.port = port;
}

void PacketFilter::set_protocol(model::IPProtocol proto) {
    config_.protocol = proto;
}

void PacketFilter::set_only_valid(bool enable) {
    config_.only_valid = enable;
}

std::optional<PacketFilter> PacketFilter::parse_expression(std::string_view expression) {
    FilterConfig config;
    std::string expr(expression);
    std::istringstream iss(expr);
    std::string token;

    while (iss >> token) {
        if (token == "tcp") {
            config.protocol = model::IPProtocol::TCP;
        } else if (token == "udp") {
            config.protocol = model::IPProtocol::UDP;
        } else if (token == "icmp") {
            config.protocol = model::IPProtocol::ICMP;
        } else if (token == "syn") {
            config.tcp_syn_only = true;
            config.protocol = model::IPProtocol::TCP;
        } else if (token == "valid") {
            config.only_valid = true;
        } else if (token == "port") {
            uint16_t p = 0;
            if (iss >> p) {
                config.port = p;
            } else {
                return std::nullopt;
            }
        } else if (token == "src" || token == "dst" || token == "host") {
            std::string next_tok;
            if (!(iss >> next_tok)) {
                return std::nullopt;
            }

            if (next_tok == "port") {
                uint16_t p = 0;
                if (iss >> p) {
                    if (token == "src") config.source_port = p;
                    else if (token == "dst") config.destination_port = p;
                    else config.port = p;
                } else {
                    return std::nullopt;
                }
            } else {
                std::string ip_str = next_tok;
                std::optional<uint8_t> cidr;
                auto slash = ip_str.find('/');
                if (slash != std::string::npos) {
                    auto prefix_str = ip_str.substr(slash + 1);
                    uint8_t prefix = 0;
                    auto [ptr, ec] = std::from_chars(prefix_str.data(), prefix_str.data() + prefix_str.size(), prefix);
                    if (ec != std::errc{} || prefix > 32) {
                        return std::nullopt;
                    }
                    cidr = prefix;
                    ip_str = ip_str.substr(0, slash);
                }

                auto ip = model::IPv4Address::from_string(ip_str);
                if (!ip) {
                    return std::nullopt;
                }

                if (token == "src") {
                    config.source_ip = ip;
                    config.source_cidr_prefix = cidr;
                } else if (token == "dst") {
                    config.destination_ip = ip;
                    config.destination_cidr_prefix = cidr;
                } else {
                    config.host_ip = ip;
                }
            }
        }
    }

    return PacketFilter(config);
}

}
