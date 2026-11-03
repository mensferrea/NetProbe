#include "netprobe/model/ipv4_packet.hpp"

namespace netprobe::model {

std::string to_string(IPProtocol proto) {
    switch (proto) {
        case IPProtocol::ICMP:
            return "ICMP (1)";
        case IPProtocol::TCP:
            return "TCP (6)";
        case IPProtocol::UDP:
            return "UDP (17)";
        default:
            return "Unknown (" + std::to_string(static_cast<uint8_t>(proto)) + ")";
    }
}

}
