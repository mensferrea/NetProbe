#include "netprobe/model/mac_address.hpp"
#include <iomanip>
#include <sstream>
#include <charconv>

namespace netprobe::model {

std::optional<MacAddress> MacAddress::from_string(std::string_view str) noexcept {
    if (str.length() != 17) {
        return std::nullopt;
    }

    RawBytes bytes{};
    size_t byte_idx = 0;

    for (size_t i = 0; i < str.length(); i += 3) {
        if (i + 2 > str.length()) {
            return std::nullopt;
        }

        if (i + 2 < str.length() && str[i + 2] != ':' && str[i + 2] != '-') {
            return std::nullopt;
        }

        uint8_t val = 0;
        auto [ptr, ec] = std::from_chars(str.data() + i, str.data() + i + 2, val, 16);
        if (ec != std::errc{} || ptr != str.data() + i + 2) {
            return std::nullopt;
        }

        bytes[byte_idx++] = val;
    }

    return MacAddress(bytes);
}

MacAddress MacAddress::broadcast() noexcept {
    return MacAddress(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
}

bool MacAddress::is_broadcast() const noexcept {
    return bytes_ == RawBytes{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
}

bool MacAddress::is_multicast() const noexcept {
    return (bytes_[0] & 0x01) == 0x01 && !is_broadcast();
}

std::string MacAddress::to_string() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < Size; ++i) {
        if (i > 0) {
            oss << ":";
        }
        oss << std::setw(2) << static_cast<unsigned int>(bytes_[i]);
    }
    return oss.str();
}

}
