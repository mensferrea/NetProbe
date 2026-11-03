#include "netprobe/capture/linux_raw_socket_source.hpp"
#include "netprobe/core/error.hpp"

#if defined(__linux__)
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <cstring>
#endif

namespace netprobe::capture {

LinuxRawSocketSource::LinuxRawSocketSource(std::string interface_name, bool promiscuous_mode)
    : interface_name_(std::move(interface_name)),
      promiscuous_mode_(promiscuous_mode) {}

LinuxRawSocketSource::~LinuxRawSocketSource() {
    close();
}

void LinuxRawSocketSource::open() {
#if defined(__linux__)
    if (socket_fd_ >= 0) {
        return;
    }

    socket_fd_ = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_fd_ < 0) {
        throw core::SocketException("Failed to open AF_PACKET raw socket: " + std::string(strerror(errno)));
    }

    if (!interface_name_.empty() && interface_name_ != "any") {
        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, interface_name_.c_str(), IFNAMSIZ - 1);
        if (::ioctl(socket_fd_, SIOCGIFINDEX, &ifr) < 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
            throw core::SocketException("Failed to get interface index for " + interface_name_ + ": " + strerror(errno));
        }
        interface_index_ = ifr.ifr_ifindex;

        struct sockaddr_ll sll{};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = interface_index_;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (::bind(socket_fd_, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
            throw core::SocketException("Failed to bind socket to " + interface_name_ + ": " + strerror(errno));
        }

        if (promiscuous_mode_) {
            enable_promiscuous_mode();
        }
    }
#else
    throw core::SocketException("LinuxRawSocketSource is only supported on Linux platform");
#endif
}

void LinuxRawSocketSource::close() {
#if defined(__linux__)
    if (socket_fd_ >= 0) {
        if (promiscuous_mode_ && interface_index_ >= 0) {
            disable_promiscuous_mode();
        }
        ::close(socket_fd_);
        socket_fd_ = -1;
        interface_index_ = -1;
    }
#endif
}

bool LinuxRawSocketSource::is_open() const noexcept {
    return socket_fd_ >= 0;
}

std::optional<core::RawPacket> LinuxRawSocketSource::receive_packet(std::chrono::milliseconds timeout) {
#if defined(__linux__)
    if (socket_fd_ < 0) {
        return std::nullopt;
    }

    struct pollfd pfd{};
    pfd.fd = socket_fd_;
    pfd.events = POLLIN;

    int poll_res = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
    if (poll_res <= 0) {
        return std::nullopt;
    }

    if (!(pfd.revents & POLLIN)) {
        return std::nullopt;
    }

    core::ByteBuffer buffer(65536);
    struct sockaddr_ll from{};
    socklen_t from_len = sizeof(from);

    ssize_t bytes_read = ::recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                   reinterpret_cast<struct sockaddr*>(&from), &from_len);
    if (bytes_read < 0) {
        return std::nullopt;
    }

    buffer.resize(static_cast<size_t>(bytes_read));

    return core::RawPacket{
        .data = std::move(buffer),
        .timestamp = std::chrono::system_clock::now(),
        .interface_name = interface_name_
    };
#else
    return std::nullopt;
#endif
}

std::string LinuxRawSocketSource::interface_name() const {
    return interface_name_;
}

void LinuxRawSocketSource::enable_promiscuous_mode() {
#if defined(__linux__)
    if (socket_fd_ < 0 || interface_index_ < 0) return;

    struct packet_mreq mr{};
    mr.mr_ifindex = interface_index_;
    mr.mr_type = PACKET_MR_PROMISC;
    ::setsockopt(socket_fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
#endif
}

void LinuxRawSocketSource::disable_promiscuous_mode() {
#if defined(__linux__)
    if (socket_fd_ < 0 || interface_index_ < 0) return;

    struct packet_mreq mr{};
    mr.mr_ifindex = interface_index_;
    mr.mr_type = PACKET_MR_PROMISC;
    ::setsockopt(socket_fd_, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mr, sizeof(mr));
#endif
}

}
