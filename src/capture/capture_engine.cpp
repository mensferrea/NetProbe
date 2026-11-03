#include "netprobe/capture/capture_engine.hpp"
#include "netprobe/parser/packet_decoder.hpp"

namespace netprobe::capture {

CaptureEngine::CaptureEngine(std::shared_ptr<IPacketSource> source)
    : source_(std::move(source)) {}

CaptureEngine::~CaptureEngine() {
    stop();
}

void CaptureEngine::add_listener(PacketCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    callbacks_.push_back(std::move(callback));
}

void CaptureEngine::start() {
    if (is_running_.exchange(true)) {
        return;
    }

    if (!source_->is_open()) {
        source_->open();
    }

    worker_thread_ = std::make_unique<std::thread>(&CaptureEngine::capture_loop, this);
}

void CaptureEngine::stop() {
    if (!is_running_.exchange(false)) {
        return;
    }

    if (worker_thread_ && worker_thread_->joinable()) {
        worker_thread_->join();
        worker_thread_.reset();
    }

    if (source_->is_open()) {
        source_->close();
    }
}

bool CaptureEngine::is_running() const noexcept {
    return is_running_.load();
}

uint64_t CaptureEngine::captured_packets_count() const noexcept {
    return packet_counter_.load();
}

uint64_t CaptureEngine::dropped_packets_count() const noexcept {
    return dropped_counter_.load();
}

void CaptureEngine::capture_loop() {
    constexpr auto poll_timeout = std::chrono::milliseconds(50);

    while (is_running_.load()) {
        auto raw_opt = source_->receive_packet(poll_timeout);
        if (!raw_opt) {
            continue;
        }

        packet_counter_.fetch_add(1, std::memory_order_relaxed);

        auto parsed_opt = parser::PacketDecoder::decode(*raw_opt);
        if (!parsed_opt) {
            dropped_counter_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        std::lock_guard<std::mutex> lock(callback_mutex_);
        for (const auto& cb : callbacks_) {
            cb(*parsed_opt, *raw_opt);
        }
    }
}

}
