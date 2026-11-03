#include "netprobe/model/ethernet_frame.hpp"

namespace netprobe::model {

std::string to_string(EtherType type) {
    switch (type) {
        case EtherType::IPv4:
            return "IPv4 (0x0800)";
        case EtherType::ARP:
            return "ARP (0x0806)";
        case EtherType::VLAN:
            return "802.1Q VLAN (0x8100)";
        case EtherType::IPv6:
            return "IPv6 (0x86DD)";
        default:
            return "Unknown";
    }
}

}
