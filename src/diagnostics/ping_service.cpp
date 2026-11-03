#include "netprobe/diagnostics/ping_service.hpp"
#include "netprobe/parser/packet_validator.hpp"
#include "netprobe/core/error.hpp"

#if defined(__linux__)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <cstring>
#endif

#include <cmath>
#include <thread>
#include <numeric>

namespace netprobe::diagnostics {

PingSummary PingService::execute(const PingRequest& request,
                                 const std::function<void(const PingResponse&)>& progress_callback) {
    PingSummary summary;
    summary.target_ip = request.target_ip;
    summary.packets_transmitted = request.count;

    std::vector<double> rtts;

    for (size_t seq = 1; seq <= request.count; ++seq) {
        auto resp = send_ping(request.target_ip, static_cast<uint16_t>(seq),
                              request.payload_size, request.timeout);

        if (resp.is_success) {
            summary.packets_received++;
            double rtt_ms = static_cast<double>(resp.rtt.count()) / 1000.0;
            rtts.push_back(rtt_ms);
        }

        if (progress_callback) {
            progress_callback(resp);
        }

        if (seq < request.count && request.interval > std::chrono::milliseconds::zero()) {
            std::this_thread::sleep_for(request.interval);
        }
    }

    if (summary.packets_transmitted > 0) {
        summary.packet_loss_percent = 100.0 * (1.0 - static_cast<double>(summary.packets_received) /
                                                      static_cast<double>(summary.packets_transmitted));
    }

    if (!rtts.empty()) {
        double min_v = rtts.front();
        double max_v = rtts.front();
        double sum = 0.0;

        for (double val : rtts) {
            min_v = std::min(min_v, val);
            max_v = std::max(max_v, val);
            sum += val;
        }

        summary.min_rtt_ms = min_v;
        summary.max_rtt_ms = max_v;
        summary.avg_rtt_ms = sum / static_cast<double>(rtts.size());

        double var_sum = 0.0;
        for (double val : rtts) {
            var_sum += (val - summary.avg_rtt_ms) * (val - summary.avg_rtt_ms);
        }
        summary.mdev_rtt_ms = std::sqrt(var_sum / static_cast<double>(rtts.size()));
    }

    return summary;
}

LinuxPingService::LinuxPingService() {
#if defined(__linux__)
    socket_fd_ = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_fd_ < 0) {
        socket_fd_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    }
    if (socket_fd_ < 0) {
        throw core::SocketException("Failed to open ICMP socket: " + std::string(strerror(errno)));
    }
    identifier_ = static_cast<uint16_t>(::getpid() & 0xFFFF);
#else
    throw core::SocketException("LinuxPingService requires Linux");
#endif
}

LinuxPingService::~LinuxPingService() {
#if defined(__linux__)
    if (socket_fd_ >= 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
#endif
}

PingResponse LinuxPingService::send_ping(const model::IPv4Address& target,
                                         uint16_t sequence,
                                         size_t payload_size,
                                         std::chrono::milliseconds timeout) {
    PingResponse resp;
    resp.sequence = sequence;

#if defined(__linux__)
    if (socket_fd_ < 0) {
        resp.error_message = "Socket closed";
        return resp;
    }

    size_t packet_size = 8 + payload_size;
    std::vector<uint8_t> buffer(packet_size, 0);

    buffer[0] = 8;
    buffer[1] = 0;
    buffer[2] = 0;
    buffer[3] = 0;
    buffer[4] = static_cast<uint8_t>((identifier_ >> 8) & 0xFF);
    buffer[5] = static_cast<uint8_t>(identifier_ & 0xFF);
    buffer[6] = static_cast<uint8_t>((sequence >> 8) & 0xFF);
    buffer[7] = static_cast<uint8_t>(sequence & 0xFF);

    for (size_t i = 8; i < packet_size; ++i) {
        buffer[i] = static_cast<uint8_t>((i - 8) & 0xFF);
    }

    uint16_t csum = parser::PacketValidator::calculate_checksum(buffer);
    buffer[2] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    buffer[3] = static_cast<uint8_t>(csum & 0xFF);

    struct sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = htonl(target.to_uint32());

    auto send_time = std::chrono::steady_clock::now();
    ssize_t sent = ::sendto(socket_fd_, buffer.data(), buffer.size(), 0,
                            reinterpret_cast<struct sockaddr*>(&dest_addr), sizeof(dest_addr));
    if (sent < 0) {
        resp.error_message = strerror(errno);
        return resp;
    }

    struct pollfd pfd{};
    pfd.fd = socket_fd_;
    pfd.events = POLLIN;

    int poll_res = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
    if (poll_res <= 0) {
        resp.error_message = (poll_res == 0) ? "Request timeout" : strerror(errno);
        return resp;
    }

    std::vector<uint8_t> recv_buf(65536);
    struct sockaddr_in from_addr{};
    socklen_t from_len = sizeof(from_addr);

    ssize_t recvd = ::recvfrom(socket_fd_, recv_buf.data(), recv_buf.size(), 0,
                              reinterpret_cast<struct sockaddr*>(&from_addr), &from_len);
    auto recv_time = std::chrono::steady_clock::now();

    if (recvd < 0) {
        resp.error_message = strerror(errno);
        return resp;
    }

    resp.rtt = std::chrono::duration_cast<std::chrono::microseconds>(recv_time - send_time);
    resp.reply_ip = model::IPv4Address(ntohl(from_addr.sin_addr.s_addr));
    resp.bytes_received = static_cast<size_t>(recvd);
    resp.ttl = (recvd >= 9) ? recv_buf[8] : 64;
    resp.is_success = true;

    return resp;
#else
    resp.error_message = "Platform unsupported";
    return resp;
#endif
}

MockPingService::MockPingService(std::vector<PingResponse> simulated_responses)
    : responses_(std::move(simulated_responses)) {}

void MockPingService::add_simulated_response(PingResponse resp) {
    responses_.push_back(std::move(resp));
}

PingResponse MockPingService::send_ping(const model::IPv4Address& target,
                                        uint16_t sequence,
                                        size_t,
                                        std::chrono::milliseconds) {
    if (current_idx_ < responses_.size()) {
        auto resp = responses_[current_idx_++];
        resp.sequence = sequence;
        return resp;
    }

    PingResponse default_resp;
    default_resp.sequence = sequence;
    default_resp.reply_ip = target;
    default_resp.ttl = 64;
    default_resp.rtt = std::chrono::microseconds(1500 + sequence * 200);
    default_resp.bytes_received = 64;
    default_resp.is_success = true;
    return default_resp;
}

}
