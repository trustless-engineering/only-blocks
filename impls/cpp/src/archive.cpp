#include "archive.hpp"

#include "net.hpp"

#include <curl/curl.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <strings.h>

#include <ctime>
#include <thread>

namespace ob {

using namespace std::chrono_literals;

namespace {

constexpr int kMaxRetries = 4;
constexpr auto kInitialBackoff = 200ms;
constexpr auto kMaxBackoff = 10'000ms;
constexpr auto kConnectTimeout = 10s;
constexpr auto kAttemptTimeout = 60s;
constexpr std::string_view kUserAgent = "onlyblocks/cpp";

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) s.remove_suffix(1);
    return s;
}

bool iequals(std::string_view a, std::string_view b) {
    return a.size() == b.size() && ::strncasecmp(a.data(), b.data(), a.size()) == 0;
}

/// Retry-After as delta-seconds or any of the three HTTP-date forms (a past date means now).
std::optional<std::chrono::milliseconds> parse_retry_after(std::string_view v) {
    v = trim(v);
    if (v.empty() || v.size() > 64) return std::nullopt;
    if (std::ranges::all_of(v, [](char c) { return c >= '0' && c <= '9'; })) {
        std::uint64_t secs = 0;
        for (char c : v) secs = std::min<std::uint64_t>(secs * 10 + static_cast<std::uint64_t>(c - '0'), 1'000'000);
        return std::chrono::seconds(secs);
    }
    std::string text(v);
    for (const char* format : {"%a, %d %b %Y %H:%M:%S GMT", "%A, %d-%b-%y %H:%M:%S GMT", "%a %b %e %H:%M:%S %Y"}) {
        std::tm tm{};
        if (const char* end = ::strptime(text.c_str(), format, &tm); end && *end == 0) {
            auto delta = std::chrono::seconds(::timegm(&tm) - std::time(nullptr));
            return std::max<std::chrono::milliseconds>(delta, 0ms);
        }
    }
    return std::nullopt;
}

/// Buffered reader over a socket with one overall deadline.
class LineReader {
public:
    LineReader(const Socket& s, Clock::time_point deadline) : s_(s), deadline_(deadline) {}

    bool fill() {
        if (pos_ < len_) return true;
        if (eof_ || error_) return false;
        auto n = s_.recv_some(buf_.data(), buf_.size(), deadline_);
        if (n < 0) error_ = true;
        else if (n == 0) eof_ = true;
        else pos_ = 0, len_ = static_cast<std::size_t>(n);
        return n > 0;
    }

    std::optional<std::string> line() {
        std::string out;
        for (;;) {
            if (!fill()) return std::nullopt;
            char c = buf_[pos_++];
            if (c == '\n') {
                if (!out.empty() && out.back() == '\r') out.pop_back();
                return out;
            }
            if (out.size() > 8192) return std::nullopt;
            out += c;
        }
    }

    /// Hands the next chunk of up to `max` buffered bytes to `sink`; false on EOF/error.
    template <class F>
    bool chunk(std::uint64_t max, F&& sink) {
        if (!fill()) return false;
        auto n = static_cast<std::size_t>(std::min<std::uint64_t>(max, len_ - pos_));
        sink(Bytes(reinterpret_cast<const std::uint8_t*>(buf_.data()) + pos_, n));
        pos_ += n;
        return true;
    }

    [[nodiscard]] bool failed() const { return error_; }

private:
    const Socket& s_;
    Clock::time_point deadline_;
    std::array<char, 16384> buf_{};
    std::size_t pos_ = 0, len_ = 0;
    bool eof_ = false, error_ = false;
};

Socket connect_to(const std::string& host, const std::string& port, Clock::time_point deadline, std::string& why) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (int rc = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &res); rc != 0) {
        why = std::format("resolve {}: {}", host, ::gai_strerror(rc));
        return {};
    }
    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> guard(res, ::freeaddrinfo);
    for (auto* ai = res; ai; ai = ai->ai_next) {
        Socket s(::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
        if (!s) continue;
        int one = 1;
        ::setsockopt(s.get(), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        ::setsockopt(s.get(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        ::fcntl(s.get(), F_SETFL, ::fcntl(s.get(), F_GETFL) | O_NONBLOCK);
        if (::connect(s.get(), ai->ai_addr, ai->ai_addrlen) == 0) return s;
        if (errno == EINPROGRESS && s.wait(POLLOUT, deadline)) {
            int err = 0;
            socklen_t len = sizeof err;
            ::getsockopt(s.get(), SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0) return s;
            errno = err;
        }
        why = std::format("connect {}:{}: {}", host, port, std::strerror(errno));
    }
    if (why.empty()) why = "connect failed";
    return {};
}

}  // namespace

struct Archive::Attempt {
    enum class Kind { Ok, Status, Transport, Fatal } kind = Kind::Transport;
    int status = 0;
    std::optional<std::chrono::milliseconds> retry_after;
    std::string why;
};

/// Receives the body: keeps exactly `length` bytes, counts the rest against `cap`.
struct Archive::Sink {
    std::uint8_t* dst;
    std::uint64_t length, cap, received = 0;
    bool over_cap = false;

    void write(Bytes b) {
        if (received < length)
            std::memcpy(dst + received, b.data(), static_cast<std::size_t>(std::min<std::uint64_t>(b.size(), length - received)));
        received += b.size();
        over_cap = over_cap || received > cap;
    }
};

Archive::Archive(std::string_view url) {
    url = trim(url);
    while (url.ends_with('/')) url.remove_suffix(1);
    std::string_view rest;
    if (url.size() >= 7 && iequals(url.substr(0, 7), "http://")) rest = url.substr(7), port_ = "80";
    else if (url.size() >= 8 && iequals(url.substr(0, 8), "https://")) rest = url.substr(8), port_ = "443", https_ = true;
    else throw std::invalid_argument("base URL must use http:// or https://");
    auto slash = rest.find('/');
    authority_ = std::string(rest.substr(0, slash));
    prefix_ = slash == std::string_view::npos ? "" : std::string(rest.substr(slash));
    std::string_view auth = authority_;
    if (auto at = auth.rfind('@'); at != std::string_view::npos) auth.remove_prefix(at + 1);
    if (auth.starts_with('[')) {
        auto close = auth.find(']');
        if (close == std::string_view::npos) throw std::invalid_argument("invalid IPv6 host in base URL");
        host_ = std::string(auth.substr(1, close - 1));
        if (auth.substr(close + 1).starts_with(':')) port_ = std::string(auth.substr(close + 2));
    } else if (auto colon = auth.rfind(':'); colon != std::string_view::npos) {
        host_ = std::string(auth.substr(0, colon));
        port_ = std::string(auth.substr(colon + 1));
    } else {
        host_ = std::string(auth);
    }
    if (host_.empty()) throw std::invalid_argument("base URL has no host");
}

double Archive::jitter() {
    std::scoped_lock lock(rng_mu_);
    return std::uniform_real_distribution<double>(0.5, 1.0)(rng_);
}

void Archive::http_attempt(const std::string& path, std::uint64_t start, std::uint64_t end, Sink& sink, Attempt& at) const {
    auto t0 = Clock::now();
    Socket s = connect_to(host_, port_, t0 + kConnectTimeout, at.why);
    if (!s) return;
    auto deadline = t0 + kAttemptTimeout;
    auto request = std::format(
        "GET {} HTTP/1.1\r\nHost: {}\r\nRange: bytes={}-{}\r\nUser-Agent: {}\r\nAccept-Encoding: identity\r\n"
        "Connection: close\r\n\r\n",
        path, authority_, start, end, kUserAgent);
    if (!s.send_all(request, deadline)) return void(at.why = "send failed");
    LineReader in(s, deadline);
    auto status_line = in.line();
    if (!status_line) return void(at.why = "no status line");
    int status = 0;
    if (std::sscanf(status_line->c_str(), "HTTP/%*d.%*d %d", &status) != 1 || status < 200 || status > 999)
        return void(at.why = "malformed status line");
    bool chunked = false;
    std::optional<std::uint64_t> content_length;
    for (;;) {
        auto line = in.line();
        if (!line) return void(at.why = "truncated headers");
        if (line->empty()) break;
        std::string_view h = *line;
        auto colon = h.find(':');
        if (colon == std::string_view::npos) continue;
        auto name = h.substr(0, colon), value = trim(h.substr(colon + 1));
        if (iequals(name, "content-length")) {
            std::uint64_t n = 0;
            auto r = std::from_chars(value.data(), value.data() + value.size(), n);
            if (r.ec != std::errc{} || r.ptr != value.data() + value.size()) return void(at.why = "bad Content-Length");
            content_length = n;
        } else if (iequals(name, "transfer-encoding")) {
            std::string lower(value);
            std::ranges::transform(lower, lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            chunked = lower.find("chunked") != std::string::npos;
        } else if (iequals(name, "retry-after")) {
            at.retry_after = parse_retry_after(value);
        }
    }
    at.status = status;
    if (status != 206) return void(at.kind = Attempt::Kind::Status);
    if (!chunked && content_length && *content_length > sink.cap) {
        at.kind = Attempt::Kind::Fatal;
        at.why = std::format("Content-Length {} exceeds the range cap", *content_length);
        return;
    }
    auto write = [&](Bytes b) { sink.write(b); };
    auto body = [&](std::uint64_t n) {
        while (n && !sink.over_cap) {
            std::uint64_t before = sink.received;
            if (!in.chunk(n, write)) return false;
            n -= sink.received - before;
        }
        return true;
    };
    if (chunked) {
        for (;;) {
            auto line = in.line();
            if (!line) return void(at.why = "truncated chunk header");
            std::uint64_t size = 0;
            auto r = std::from_chars(line->data(), line->data() + line->size(), size, 16);
            if (r.ec != std::errc{} || (r.ptr != line->data() + line->size() && *r.ptr != ';' && *r.ptr != ' '))
                return void(at.why = "bad chunk size");
            if (size == 0) {
                for (;;) {
                    auto trailer = in.line();
                    if (!trailer) return void(at.why = "truncated trailers");
                    if (trailer->empty()) break;
                }
                break;
            }
            if (!body(size)) return void(at.why = "truncated chunk");
            if (sink.over_cap) break;
            if (auto crlf = in.line(); !crlf || !crlf->empty()) return void(at.why = "bad chunk terminator");
        }
    } else if (content_length) {
        if (!body(*content_length)) return void(at.why = "connection closed mid-body");
    } else {
        while (!sink.over_cap && in.chunk(UINT64_MAX, write)) {
        }
        if (in.failed()) return void(at.why = "read error");
    }
    if (sink.over_cap) {
        at.kind = Attempt::Kind::Fatal;
        at.why = "range body exceeds its cap";
        return;
    }
    at.kind = Attempt::Kind::Ok;
}

void Archive::https_attempt(const std::string& path, std::uint64_t start, std::uint64_t end, Sink& sink, Attempt& at) const {
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl) return void(at.why = "curl_easy_init failed");
    struct State {
        CURL* curl;
        Sink& sink;
        Attempt& at;
        bool fatal = false;
        [[nodiscard]] long code() const {
            long c = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &c);
            return c;
        }
    } state{curl.get(), sink, at};
    auto on_header = +[](char* p, std::size_t size, std::size_t n, void* ud) -> std::size_t {
        auto& st = *static_cast<State*>(ud);
        std::string_view h(p, size * n);
        auto colon = h.find(':');
        if (colon != std::string_view::npos) {
            auto name = h.substr(0, colon), value = trim(h.substr(colon + 1));
            if (iequals(name, "retry-after")) st.at.retry_after = parse_retry_after(value);
            std::uint64_t length = 0;
            if (iequals(name, "content-length") && std::from_chars(value.data(), value.data() + value.size(), length).ec == std::errc{} &&
                st.code() == 206 && length > st.sink.cap) {
                st.fatal = true;
                return 0;  // abort the transfer
            }
        }
        return size * n;
    };
    auto on_body = +[](char* p, std::size_t size, std::size_t n, void* ud) -> std::size_t {
        auto& st = *static_cast<State*>(ud);
        if (st.code() != 206) return size * n;  // status-only responses: discard the body
        st.sink.write(Bytes(reinterpret_cast<const std::uint8_t*>(p), size * n));
        if (st.sink.over_cap) {
            st.fatal = true;
            return 0;
        }
        return size * n;
    };
    auto url = std::format("https://{}{}", authority_, path);
    auto range = std::format("{}-{}", start, end);
    CURL* h = curl.get();
    curl_easy_setopt(h, CURLOPT_URL, url.c_str());
    curl_easy_setopt(h, CURLOPT_RANGE, range.c_str());
    curl_easy_setopt(h, CURLOPT_USERAGENT, kUserAgent.data());
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(std::chrono::milliseconds(kConnectTimeout).count()));
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, static_cast<long>(std::chrono::milliseconds(kAttemptTimeout).count()));
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, on_header);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, &state);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &state);
    CURLcode rc = curl_easy_perform(h);
    long code = state.code();
    if (state.fatal) {
        at.kind = Attempt::Kind::Fatal;
        at.why = "range body exceeds its cap";
    } else if (rc != CURLE_OK) {
        if (code != 0 && code != 206) at.kind = Attempt::Kind::Status, at.status = static_cast<int>(code);
        else at.why = std::format("https: {}", curl_easy_strerror(rc));
    } else {
        at.status = static_cast<int>(code);
        at.kind = code == 206 ? Attempt::Kind::Ok : Attempt::Kind::Status;
    }
}

Bytes Archive::read_range(std::uint64_t slot, std::string_view suffix, std::uint64_t start, std::uint64_t length,
                          std::uint64_t cap, Arena& arena) {
    require(length > 0 && start <= UINT64_MAX - (length - 1), "archive range end overflows u64");
    std::uint64_t end = start + length - 1, epoch = slot / kSlotsPerEpoch;
    auto path = std::format("{}/{}/epoch-{}{}", prefix_, epoch, epoch, suffix);
    std::vector<std::uint8_t> body(static_cast<std::size_t>(length));
    for (int failures = 0;; ++failures) {
        Sink sink{body.data(), length, cap};
        Attempt at;
        {
            inflight_.acquire();  // a slot is held only while an attempt is in flight
            struct Release {
                std::counting_semaphore<32>& s;
                ~Release() { s.release(); }
            } release{inflight_};
            if (https_) https_attempt(path, start, end, sink, at);
            else http_attempt(path, start, end, sink, at);
        }
        switch (at.kind) {
            case Attempt::Kind::Ok:
                require(sink.received == length,
                        std::format("archive range body has {} bytes, expected {}", sink.received, length));
                return arena.keep(std::move(body));
            case Attempt::Kind::Fatal: fail(std::format("archive range read failed: {}", at.why));
            case Attempt::Kind::Status:
                if (at.status == 404)
                    throw RpcError(code::unarchived,
                                   std::format("Block not available for slot {}: epoch {} is not archived in Old Faithful "
                                               "(historical-only server)",
                                               slot, epoch));
                if (at.status != 429 && (at.status < 500 || at.status > 599))
                    fail(std::format("unexpected archive HTTP status {}", at.status));
                break;
            case Attempt::Kind::Transport: break;
        }
        if (failures == kMaxRetries)
            fail(at.kind == Attempt::Kind::Status ? std::format("archive retries exhausted (HTTP {})", at.status)
                                                  : std::format("archive retries exhausted: {}", at.why));
        std::chrono::milliseconds delay;
        if (at.retry_after) {
            delay = std::min(*at.retry_after, std::chrono::duration_cast<std::chrono::milliseconds>(kMaxBackoff));
        } else {
            auto base = std::min<std::chrono::milliseconds>(kInitialBackoff * (1LL << std::min(failures, 30)), kMaxBackoff);
            delay = std::chrono::milliseconds(static_cast<long long>(static_cast<double>(base.count()) * jitter()));
        }
        if (delay > 0ms) std::this_thread::sleep_for(delay);
    }
}

Bytes Archive::slot_slice(std::uint64_t slot, Arena& arena) {
    auto range = ranges_.get(slot);
    if (!range) {
        auto record = read_range(slot, "-slot-ranges.raw", (slot % kSlotsPerEpoch) * 12, 12, 12, arena);
        range = SlotRange{load_le<std::uint64_t>(record.data()), load_le<std::uint32_t>(record.data() + 8)};
        ranges_.put(slot, *range);
    }
    if (range->length == 0) throw RpcError(code::skipped, std::format("Slot {} was skipped, or missing in long-term storage", slot));
    require(range->length <= kMaxSlice, "slot slice exceeds the 128 MiB cap");
    return read_range(slot, ".car", range->offset, range->length, kMaxSlice, arena);
}

}  // namespace ob
