#include "netprobe/model/tcp_segment.hpp"
#include <vector>
#include <numeric>

namespace netprobe::model {

std::string TcpFlags::to_string() const {
    std::string result;
    if (syn) result += "SYN ";
    if (ack) result += "ACK ";
    if (fin) result += "FIN ";
    if (rst) result += "RST ";
    if (psh) result += "PSH ";
    if (urg) result += "URG ";
    if (ece) result += "ECE ";
    if (cwr) result += "CWR ";
    if (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }
    return result.empty() ? "NONE" : result;
}

}
