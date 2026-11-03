#include "netprobe/model/ip_address.hpp"
#include <charconv>
#include <sstream>

namespace netprobe::model {

std::optional<IPv4Address> IPv4Address::from_string(std::string_view str) noexcept {
    if (str.empty()) {
        return std::nullopt;
    }

    uint32_t octets[4] = {0, 0, 0, 0};
    size_t current_octet = 0;
    size_t start = 0;

    for (size_t i = 0; i <= str.size(); ++i) {
        if (i == str.size() || str[i] == '.') {
            if (start == i || current_octet >= 4) {
                return std::nullopt;
            }

            uint32_t val = 0;
            auto [ptr, ec] = std::from_chars(str.data() + start, str.data() + i, val);
            if (ec != std::errc{} || ptr != str.data() + i || val > 255) {
                return std::nullopt;
            }

            octets[current_octet++] = val;
            start = i + 1;
        }
    }

    if (current_octet != 4) {
        return std::nullopt;
    }

    return IPv4Address(
        static_cast<uint8_t>(octets[0]),
        static_cast<uint8_t>(octets[1]),
        static_cast<uint8_t>(octets[2]),
        static_cast<uint8_t>(octets[3])
    );
}

std::string IPv4Address::to_string() const {
    std::ostringstream oss;
    oss << static_cast<unsigned int>(octet(0)) << '.'
        << static_cast<unsigned int>(octet(1)) << '.'
        << static_cast<unsigned int>(octet(2)) << '.'
        << static_cast<unsigned int>(octet(3));
    return oss.str();
}

bool IPv4Address::matches_cidr(const IPv4Address& network, uint8_t prefix_length) const noexcept {
    if (prefix_length == 0) {
        return true;
    }
    if (prefix_length > 32) {
        return false;
    }
    uint32_t mask = (prefix_length == 32) ? 0xFFFFFFFFU : ~((1U << (32 - prefix_length)) - 1U);
    return (address_ & mask) == (network.address_ & mask);
}

}
