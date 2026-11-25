// OnlyBlocks C++20 server: CLI, HTTP/1.1 listener, one thread per connection, JSON-RPC 2.0 dispatch.
#include "block.hpp"
#include "json.hpp"
#include "net.hpp"

#include <curl/curl.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <strings.h>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <iostream>
#include <thread>

namespace ob {
namespace {

using namespace std::chrono_literals;

constexpr std::size_t kMaxHeader = 64 * 1024;
constexpr std::size_t kMaxBatch = 100;
constexpr auto kIoTimeout = 60s;

std::atomic<int> g_active{0};
int g_wake[2] = {-1, -1};

// ================================================================ JSON-RPC

struct Response {
    std::string& out;

    void error(int code, std::string_view message, std::string_view id) {
        out += R"({"jsonrpc":"2.0","error":{"code":)";
        out += std::to_string(code);
        out += R"(,"message":)";
        append_json_string(out, message);
        out += R"(},"id":)";
        out += id;
        out += '}';
    }
};

/// A JSON integer literal (`0|[1-9][0-9]*`) up to `max`, validated on its source text.
std::optional<std::uint64_t> integer_literal(const Json* v, std::uint64_t max) {
    if (!v || !v->is(Json::Kind::Number) || v->raw.size() > 20) return std::nullopt;
    if (v->raw.size() > 1 && v->raw[0] == '0') return std::nullopt;
    if (!std::ranges::all_of(v->raw, [](char c) { return c >= '0' && c <= '9'; })) return std::nullopt;
    return parse_unsigned(v->raw, max);
}

template <class E, std::size_t N>
bool pick(const Json* v, const std::array<std::pair<std::string_view, E>, N>& names, E& out) {
    if (!v || v->is(Json::Kind::Null)) return true;  // null means default
    if (!v->is(Json::Kind::String)) return false;
    for (const auto& [name, value] : names)
        if (v->text == name) return out = value, true;
    return false;
}

constexpr std::array<std::pair<std::string_view, Encoding>, 4> kEncodings{
    {{"json", Encoding::Json}, {"jsonParsed", Encoding::JsonParsed}, {"base64", Encoding::Base64}, {"base58", Encoding::Base58}}};
constexpr std::array<std::pair<std::string_view, Details>, 4> kDetails{
    {{"full", Details::Full}, {"accounts", Details::Accounts}, {"signatures", Details::Signatures}, {"none", Details::None}}};

std::optional<BlockOptions> block_options(const Json* params) {
    if (!params || !params->is(Json::Kind::Array) || params->items.empty() || params->items.size() > 2) return std::nullopt;
    BlockOptions o;
    auto slot = integer_literal(&params->items[0], UINT64_MAX);
    if (!slot) return std::nullopt;
    o.slot = *slot;
    if (params->items.size() == 1) return o;
    const Json& config = params->items[1];
    if (config.is(Json::Kind::Null)) return o;
    if (config.is(Json::Kind::String)) {
        if (!pick(&config, kEncodings, o.encoding)) return std::nullopt;
        return o;
    }
    if (!config.is(Json::Kind::Object)) return std::nullopt;  // unknown keys are ignored
    if (!pick(config.get("encoding"), kEncodings, o.encoding)) return std::nullopt;
    if (!pick(config.get("transactionDetails"), kDetails, o.details)) return std::nullopt;
    if (const auto* r = config.get("rewards"); r && !r->is(Json::Kind::Null)) {
        if (!r->is(Json::Kind::True) && !r->is(Json::Kind::False)) return std::nullopt;
        o.rewards = r->is(Json::Kind::True);
    }
    if (const auto* m = config.get("maxSupportedTransactionVersion"); m && !m->is(Json::Kind::Null)) {
        auto v = integer_literal(m, 255);
        if (!v) return std::nullopt;
        o.max_version = static_cast<std::uint8_t>(*v);
    }
    if (const auto* c = config.get("commitment");
        c && !c->is(Json::Kind::Null) && !c->is_string("finalized") && !c->is_string("confirmed"))
        return std::nullopt;
    if (o.details == Details::Accounts && o.encoding != Encoding::Json) return std::nullopt;
    return o;
}

void dispatch(Archive& archive, const Json& request, std::string& out) {
    Response r{out};
    if (!request.is(Json::Kind::Object)) return r.error(code::invalid_request, "Invalid Request", "null");
    const Json *jsonrpc = request.get("jsonrpc"), *method = request.get("method"), *id = request.get("id");
    auto string_or_null = [](const Json* v) { return !v || v->is(Json::Kind::String) || v->is(Json::Kind::Null); };
    if (!string_or_null(jsonrpc) || !string_or_null(method) ||
        (id && !id->is(Json::Kind::String) && !id->is(Json::Kind::Number) && !id->is(Json::Kind::Null)))
        return r.error(code::invalid_request, "Invalid Request", "null");
    std::string_view echo = id && !id->is(Json::Kind::Null) ? id->raw : "null";
    if (!jsonrpc || !jsonrpc->is_string("2.0") || !method || !method->is(Json::Kind::String))
        return r.error(code::invalid_request, "Invalid Request", echo);
    const Json* params = request.get("params");
    if (method->text == "getHealth") {
        if (params && !params->is(Json::Kind::Null) && !(params->is(Json::Kind::Array) && params->items.empty()))
            return r.error(code::params, "Invalid params: getHealth takes no parameters", echo);
        out += R"({"jsonrpc":"2.0","result":"ok","id":)";
        out += echo;
        out += '}';
        return;
    }
    if (method->text != "getBlock")  // getTransaction included: no params parsing, no network
        return r.error(code::method, std::format("Method not found: {}", method->text), echo);
    auto options = block_options(params);
    if (!options) return r.error(code::params, "Invalid params", echo);
    auto mark = out.size();
    try {
        out += R"({"jsonrpc":"2.0","result":)";
        JsonWriter w(out);
        get_block(archive, *options, w);
        out += R"(,"id":)";
        out += echo;
        out += '}';
    } catch (const RpcError& e) {
        out.resize(mark);
        r.error(e.code, e.what(), echo);
    } catch (const std::exception& e) {  // DecodeError, bad_alloc, length_error, ...
        out.resize(mark);
        r.error(code::internal, std::format("Internal error: {}", e.what()), echo);
    }
}

std::string handle_rpc(Archive& archive, std::string_view body) {
    std::string out;
    Response r{out};
    Json root;
    try {
        root = parse_json(body);
    } catch (const JsonParseError&) {
        r.error(code::parse, "Parse error", "null");
        return out;
    }
    if (!root.is(Json::Kind::Array)) {
        dispatch(archive, root, out);
    } else if (root.items.empty() || root.items.size() > kMaxBatch) {
        r.error(code::invalid_request, "Invalid Request", "null");
    } else {
        out += '[';
        for (std::size_t i = 0; i < root.items.size(); ++i) {  // sequential, in order
            if (i) out += ',';
            dispatch(archive, root.items[i], out);
        }
        out += ']';
    }
    return out;
}

// ================================================================ HTTP

void send_status(const Socket& s, int status, std::string_view reason) {
    s.send_all(std::format("HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, reason),
               Clock::now() + kIoTimeout);
}

/// After an early reply, read what the client is still sending so close() does not reset the reply.
void drain(const Socket& s) {
    ::shutdown(s.get(), SHUT_WR);
    std::array<char, 16384> buf{};
    auto deadline = Clock::now() + 2s;
    for (std::size_t total = 0; total < 4 * kMiB;) {
        auto n = s.recv_some(buf.data(), buf.size(), deadline);
        if (n <= 0) break;
        total += static_cast<std::size_t>(n);
    }
}

std::optional<std::string_view> header(std::string_view head, std::string_view name) {
    std::optional<std::string_view> found;
    for (std::size_t pos = head.find('\n'); pos != std::string_view::npos && pos + 1 < head.size();) {
        auto end = head.find('\n', pos + 1);
        auto line = head.substr(pos + 1, end == std::string_view::npos ? std::string_view::npos : end - pos - 1);
        if (line.ends_with('\r')) line.remove_suffix(1);
        if (line.size() > name.size() && line[name.size()] == ':' && ::strncasecmp(line.data(), name.data(), name.size()) == 0) {
            auto v = line.substr(name.size() + 1);
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
            while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
            found = v;
        }
        pos = end;
    }
    return found;
}

class Connection {
public:
    Connection(Socket s, Archive& archive) : s_(std::move(s)), archive_(archive), deadline_(Clock::now() + kIoTimeout) {}

    void serve() {
        std::size_t head_end;
        while ((head_end = buf_.find("\r\n\r\n")) == std::string::npos) {
            if (buf_.size() > kMaxHeader || !fill()) return;
        }
        std::string_view head(buf_.data(), head_end + 2);
        if (head.size() > kMaxHeader) return send_status(s_, 431, "Request Header Fields Too Large");
        auto request_line = head.substr(0, head.find('\n'));
        auto sp1 = request_line.find(' '), sp2 = request_line.find(' ', sp1 + 1);
        if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) return send_status(s_, 400, "Bad Request");
        auto method = request_line.substr(0, sp1), target = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
        auto te = header(head, "transfer-encoding");
        bool chunked = te && std::string_view(*te).find("chunked") != std::string_view::npos;
        std::optional<std::uint64_t> length;
        if (auto cl = header(head, "content-length")) {
            std::uint64_t n = 0;
            auto r = std::from_chars(cl->data(), cl->data() + cl->size(), n);
            if (r.ptr != cl->data() + cl->size() || cl->empty()) return send_status(s_, 400, "Bad Request");
            length = r.ec == std::errc{} ? n : UINT64_MAX;
        }
        if (target != "/") return send_status(s_, 404, "Not Found"), drain(s_);
        if (method != "POST") return send_status(s_, 405, "Method Not Allowed"), drain(s_);
        if (!chunked && length && *length > kMaxBody) return send_status(s_, 413, "Payload Too Large"), drain(s_);
        if (auto expect = header(head, "expect"); expect && ::strncasecmp(expect->data(), "100-continue", 12) == 0)
            s_.send_all("HTTP/1.1 100 Continue\r\n\r\n", deadline_);
        std::string body;
        std::size_t pos = head_end + 4;
        if (chunked) {
            bool too_big = false;
            if (!read_chunked(pos, body, too_big)) {
                if (too_big) return send_status(s_, 413, "Payload Too Large"), drain(s_);
                return send_status(s_, 400, "Bad Request");
            }
        } else {
            auto want = static_cast<std::size_t>(length.value_or(0));
            while (buf_.size() - pos < want)
                if (!fill()) return;
            body = buf_.substr(pos, want);
        }
        std::string reply = handle_rpc(archive_, body);
        auto head_out = std::format("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n"
                                    "Connection: close\r\n\r\n",
                                    reply.size());
        auto deadline = Clock::now() + kIoTimeout;
        if (s_.send_all(head_out, deadline)) s_.send_all(reply, deadline);
        ::shutdown(s_.get(), SHUT_WR);
    }

private:
    bool fill() {
        std::array<char, 65536> chunk;
        auto n = s_.recv_some(chunk.data(), chunk.size(), deadline_);
        if (n <= 0) return false;
        buf_.append(chunk.data(), static_cast<std::size_t>(n));
        return true;
    }

    std::optional<std::string_view> line_at(std::size_t& pos) {
        std::size_t nl;
        while ((nl = buf_.find('\n', pos)) == std::string::npos)
            if (buf_.size() > kMaxHeader + 2 * kMaxBody || !fill()) return std::nullopt;
        std::string_view line(buf_.data() + pos, nl - pos);
        pos = nl + 1;
        if (line.ends_with('\r')) line.remove_suffix(1);
        return line;
    }

    bool read_chunked(std::size_t pos, std::string& body, bool& too_big) {
        for (;;) {
            auto line = line_at(pos);
            if (!line) return false;
            std::uint64_t size = 0;
            auto r = std::from_chars(line->data(), line->data() + line->size(), size, 16);
            if (r.ptr == line->data()) return false;
            if (size == 0) {
                for (;;) {  // trailers
                    auto trailer = line_at(pos);
                    if (!trailer) return false;
                    if (trailer->empty()) return true;
                }
            }
            if (r.ec != std::errc{} || size > kMaxBody - body.size()) return too_big = true, false;
            while (buf_.size() - pos < size + 2)
                if (!fill()) return false;
            body.append(buf_, pos, static_cast<std::size_t>(size));
            pos += static_cast<std::size_t>(size);
            auto crlf = line_at(pos);
            if (!crlf || !crlf->empty()) return false;
        }
    }

    Socket s_;
    Archive& archive_;
    Clock::time_point deadline_;
    std::string buf_;
};

Socket listen_on(std::string_view bind) {
    std::string host, port;
    if (bind.starts_with('[')) {
        auto close = bind.find(']');
        if (close == std::string_view::npos || bind.substr(close + 1, 1) != ":")
            throw std::invalid_argument("bind address must be HOST:PORT");
        host = bind.substr(1, close - 1);
        port = bind.substr(close + 2);
    } else {
        auto colon = bind.rfind(':');
        if (colon == std::string_view::npos) throw std::invalid_argument("bind address must be HOST:PORT");
        host = bind.substr(0, colon);
        port = bind.substr(colon + 1);
    }
    unsigned p = 0;
    if (auto r = std::from_chars(port.data(), port.data() + port.size(), p);
        port.empty() || r.ptr != port.data() + port.size() || p > 65535)
        throw std::invalid_argument("invalid port in bind address");
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    addrinfo* res = nullptr;
    if (int rc = ::getaddrinfo(host.empty() ? nullptr : host.c_str(), port.c_str(), &hints, &res); rc != 0)
        throw std::runtime_error(std::format("resolve {}: {}", host, ::gai_strerror(rc)));
    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> guard(res, ::freeaddrinfo);
    std::string why = "no usable address";
    for (auto* ai = res; ai; ai = ai->ai_next) {
        Socket s(::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol));
        if (!s) continue;
        int one = 1;
        ::setsockopt(s.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (::bind(s.get(), ai->ai_addr, ai->ai_addrlen) == 0 && ::listen(s.get(), 512) == 0) return s;
        why = std::strerror(errno);
    }
    throw std::runtime_error(std::format("bind {}: {}", bind, why));
}

extern "C" void on_signal(int) {
    char b = 1;
    [[maybe_unused]] auto r = ::write(g_wake[1], &b, 1);
}

int run(int argc, char** argv) {
    auto env = [](const char* name, std::string_view fallback) {
        const char* v = std::getenv(name);
        return std::string(v ? v : fallback);
    };
    std::string bind = env("ONLYBLOCKS_BIND", "127.0.0.1:8899");
    std::string base = env("OLD_FAITHFUL_BASE_URL", "https://files.old-faithful.net");
    std::vector<std::string_view> args(argv + 1, argv + argc);
    for (std::size_t i = 0; i < args.size(); ++i) {
        auto arg = args[i];
        if (arg == "--help" || arg == "-h") {
            std::cerr << "usage: onlyblocks [--bind HOST:PORT] [--base-url URL]\n";
            return 0;
        }
        std::string* target = nullptr;
        std::string_view name;
        for (auto [flag, dest] : {std::pair{std::string_view("--bind"), &bind}, std::pair{std::string_view("--base-url"), &base}})
            if (arg == flag || (arg.starts_with(flag) && arg.size() > flag.size() && arg[flag.size()] == '='))
                target = dest, name = flag;
        if (!target) {
            std::cerr << "onlyblocks: unknown option " << arg << '\n';
            return 2;
        }
        if (arg.size() > name.size()) {
            *target = std::string(arg.substr(name.size() + 1));
        } else if (i + 1 < args.size()) {
            *target = std::string(args[++i]);
        } else {
            std::cerr << "onlyblocks: missing value for " << name << '\n';
            return 2;
        }
    }
    std::optional<Archive> archive;
    try {
        archive.emplace(base);
    } catch (const std::invalid_argument& e) {
        std::cerr << "onlyblocks: " << e.what() << '\n';
        return 2;
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        std::cerr << "onlyblocks: curl_global_init failed\n";
        return 1;
    }
    std::signal(SIGPIPE, SIG_IGN);
    if (::pipe(g_wake) != 0) return 1;
    ::fcntl(g_wake[1], F_SETFL, O_NONBLOCK);
    struct sigaction sa {};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    ::sigaction(SIGINT, &sa, nullptr);
    ::sigaction(SIGTERM, &sa, nullptr);
    Socket listener = listen_on(bind);
    std::cerr << std::format("onlyblocks/cpp listening on {} (archive {})\n", bind, base);
    for (;;) {
        pollfd fds[2] = {{listener.get(), POLLIN, 0}, {g_wake[0], POLLIN, 0}};
        if (::poll(fds, 2, -1) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (fds[1].revents) break;
        if (!(fds[0].revents & POLLIN)) continue;
        Socket client(::accept(listener.get(), nullptr, nullptr));
        if (!client) continue;
        int one = 1;
        ::setsockopt(client.get(), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        ::setsockopt(client.get(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        ++g_active;
        try {
            std::thread([s = std::move(client), &a = *archive]() mutable {
                try {
                    Connection(std::move(s), a).serve();
                } catch (...) {  // nothing escapes a connection thread
                }
                --g_active;
            }).detach();
        } catch (const std::system_error&) {
            --g_active;
        }
    }
    listener.reset();
    for (auto deadline = Clock::now() + 1500ms; g_active > 0 && Clock::now() < deadline;) std::this_thread::sleep_for(20ms);
    std::cerr << "onlyblocks/cpp shutting down\n";
    std::_Exit(0);
}

}  // namespace
}  // namespace ob

int main(int argc, char** argv) {
    try {
        return ob::run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "onlyblocks: " << e.what() << '\n';
        return 1;
    }
}
