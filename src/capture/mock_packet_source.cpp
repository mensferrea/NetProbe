#include "netprobe/capture/mock_packet_source.hpp"
#include <thread>

namespace netprobe::capture {

MockPacketSource::MockPacketSource(std::string interface_name)
    : interface_name_(std::move(interface_name)) {}

void MockPacketSource::open() {
    std::lock_guard<std::mutex> lock(mutex_);
    is_open_ = true;
}

void MockPacketSource::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    is_open_ = false;
}

bool MockPacketSource::is_open() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return is_open_;
}

std::optional<core::RawPacket> MockPacketSource::receive_packet(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (!is_open_) {
        return std::nullopt;
    }

    if (!packet_queue_.empty()) {
        auto pkt = std::move(packet_queue_.front());
        packet_queue_.pop_front();
        return pkt;
    }

    lock.unlock();
    if (timeout > std::chrono::milliseconds::zero()) {
        std::this_thread::sleep_for(timeout);
    }
    return std::nullopt;
}

std::string MockPacketSource::interface_name() const {
    return interface_name_;
}

void MockPacketSource::inject_packet(core::RawPacket packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    packet_queue_.push_back(std::move(packet));
}

void MockPacketSource::inject_packet(core::ByteBuffer data) {
    core::RawPacket pkt{
        .data = std::move(data),
        .timestamp = std::chrono::system_clock::now(),
        .interface_name = interface_name_
    };
    inject_packet(std::move(pkt));
}

void MockPacketSource::inject_packets(std::vector<core::ByteBuffer> packets) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& data : packets) {
        packet_queue_.push_back(core::RawPacket{
            .data = std::move(data),
            .timestamp = std::chrono::system_clock::now(),
            .interface_name = interface_name_
        });
    }
}

size_t MockPacketSource::remaining_packets() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return packet_queue_.size();
}

}
