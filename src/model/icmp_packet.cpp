#include "netprobe/model/icmp_packet.hpp"

namespace netprobe::model {

std::string to_string(IcmpType type) {
    switch (type) {
        case IcmpType::EchoReply:
            return "Echo Reply (0)";
        case IcmpType::DestinationUnreachable:
            return "Destination Unreachable (3)";
        case IcmpType::SourceQuench:
            return "Source Quench (4)";
        case IcmpType::Redirect:
            return "Redirect (5)";
        case IcmpType::EchoRequest:
            return "Echo Request (8)";
        case IcmpType::TimeExceeded:
            return "Time Exceeded (11)";
        case IcmpType::ParameterProblem:
            return "Parameter Problem (12)";
        case IcmpType::TimestampRequest:
            return "Timestamp Request (13)";
        case IcmpType::TimestampReply:
            return "Timestamp Reply (14)";
        default:
            return "Unknown";
    }
}

}
