// RAII sockets and deadline-bounded blocking I/O over POSIX.
#pragma once

#include <algorithm>
#include <chrono>
#include <string_view>
#include <utility>

#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace ob {

using Clock = std::chrono::steady_clock;

/// Owns one file descriptor; move-only, closed on destruction.
class Socket {
public:
    Socket() = default;
    explicit Socket(int fd) : fd_(fd) {}
    Socket(Socket&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    ~Socket() { reset(); }

    [[nodiscard]] int get() const { return fd_; }
    explicit operator bool() const { return fd_ >= 0; }
    void reset() {
        if (fd_ >= 0) ::close(std::exchange(fd_, -1));
    }

    /// Waits for `events` until `deadline`; false on timeout or error.
    [[nodiscard]] bool wait(short events, Clock::time_point deadline) const {
        for (;;) {
            auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
            if (left <= 0) return false;
            pollfd p{fd_, events, 0};
            int r = ::poll(&p, 1, static_cast<int>(std::min<long long>(left, 1'000'000)));
            if (r < 0 && errno == EINTR) continue;
            return r > 0;
        }
    }

    /// Sends everything or returns false.
    bool send_all(std::string_view data, Clock::time_point deadline) const {
        while (!data.empty()) {
            auto n = ::send(fd_, data.data(), data.size(), 0);
            if (n > 0) {
                data.remove_prefix(static_cast<std::size_t>(n));
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && wait(POLLOUT, deadline)) continue;
            return false;
        }
        return true;
    }

    /// Up to `n` bytes; 0 on EOF, -1 on error or timeout.
    long recv_some(char* buf, std::size_t n, Clock::time_point deadline) const {
        for (;;) {
            if (!wait(POLLIN, deadline)) return -1;
            auto r = ::recv(fd_, buf, n, 0);
            if (r < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            return r;
        }
    }

private:
    int fd_ = -1;
};

}  // namespace ob
