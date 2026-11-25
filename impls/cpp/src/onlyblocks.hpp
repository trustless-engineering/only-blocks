// OnlyBlocks C++20 server: shared vocabulary types, checked readers, codecs and the JSON writer.
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <format>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ob {

using Bytes = std::span<const std::uint8_t>;

inline constexpr std::size_t kMiB = 1024 * 1024;
inline constexpr std::uint64_t kSlotsPerEpoch = 432'000;
inline constexpr std::uint64_t kBincodeCutoff = 157 * kSlotsPerEpoch;
inline constexpr std::size_t kMaxSlice = 128 * kMiB;
inline constexpr std::size_t kMaxDecompressed = 512 * kMiB;
inline constexpr std::size_t kMaxBody = kMiB;

namespace code {
inline constexpr int parse = -32700, invalid_request = -32600, method = -32601, params = -32602, internal = -32603,
                     unarchived = -32004, skipped = -32007, version = -32015;
}

/// Any malformed byte anywhere: always reported as -32603.
struct DecodeError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

/// A JSON-RPC error with its own code (-32004, -32007, -32015, ...).
struct RpcError : std::runtime_error {
    int code;
    RpcError(int c, const std::string& message) : std::runtime_error(message), code(c) {}
};

[[noreturn]] inline void fail(std::string_view what) { throw DecodeError(std::string(what)); }
inline void require(bool ok, std::string_view what) {
    if (!ok) fail(what);
}

inline std::string_view as_chars(Bytes b) { return {reinterpret_cast<const char*>(b.data()), b.size()}; }
inline Bytes as_bytes(std::string_view s) { return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()}; }

template <class T>
constexpr T load_le(const std::uint8_t* p) {
    T v = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) v |= static_cast<T>(static_cast<T>(p[i]) << (8 * i));
    return v;
}

/// The single bounds-checked cursor that every binary decoder reads through.
class Reader {
public:
    explicit Reader(Bytes data) : data_(data) {}
    [[nodiscard]] std::size_t pos() const { return pos_; }
    [[nodiscard]] std::size_t remaining() const { return data_.size() - pos_; }
    [[nodiscard]] bool empty() const { return pos_ == data_.size(); }
    [[nodiscard]] Bytes data() const { return data_; }
    [[nodiscard]] Bytes consumed() const { return data_.first(pos_); }
    [[nodiscard]] std::uint8_t peek() const {
        require(!empty(), "truncated input");
        return data_[pos_];
    }
    Bytes take(std::uint64_t n) {
        require(n <= remaining(), "truncated input");
        auto out = data_.subspan(pos_, static_cast<std::size_t>(n));
        pos_ += static_cast<std::size_t>(n);
        return out;
    }
    Bytes rest() { return take(remaining()); }
    std::uint8_t u8() { return take(1)[0]; }
    template <class T>
    T le() {
        return load_le<T>(take(sizeof(T)).data());
    }
    std::uint64_t be(int n) {
        std::uint64_t v = 0;
        for (auto b : take(static_cast<std::uint64_t>(n))) v = v << 8 | b;
        return v;
    }
    /// Unsigned LEB128, at most 10 bytes (WIRE_FORMATS.md §3.1, §10.1).
    std::uint64_t uvarint() {
        std::uint64_t x = 0;
        for (int i = 0; i < 10; ++i) {
            auto b = u8();
            if (i == 9 && b > 1) fail("varint overflow");
            x |= static_cast<std::uint64_t>(b & 0x7F) << (7 * i);
            if (b < 0x80) return x;
        }
        fail("varint overflow");
    }

private:
    Bytes data_;
    std::size_t pos_ = 0;
};

/// Owns decoded buffers for one request so spans and string_views into them stay valid.
class Arena {
public:
    Bytes keep(std::vector<std::uint8_t>&& v) { return buffers_.emplace_back(std::move(v)); }

private:
    std::deque<std::vector<std::uint8_t>> buffers_;
};

// ---- hashes (core.cpp) --------------------------------------------------------------
std::uint64_t crc64_go_iso(Bytes data);
std::uint64_t fnv1a64(Bytes data);
std::uint64_t xxh64(Bytes data);

// ---- text ------------------------------------------------------------------------
bool valid_utf8(Bytes data);
/// Rust `from_str` for unsigned integers: optional '+', ASCII digits, must fit `max`.
std::optional<std::uint64_t> parse_unsigned(std::string_view s, std::uint64_t max);
/// real_number_string_trimmed (WIRE_FORMATS.md §15.4).
std::string ui_amount_string(std::uint64_t amount, unsigned decimals);
void append_base58(std::string& out, Bytes data);
void append_base64(std::string& out, Bytes data);
std::string base58(Bytes data);
void append_json_string(std::string& out, std::string_view s);

// ---- JSON writer -----------------------------------------------------------------
struct RawJson {
    std::string_view text;
};
struct Base58 {
    Bytes bytes;
};
struct Base64 {
    Bytes bytes;
};

/// Streaming JSON writer: nesting is lexical (`object([&]{ ... })`), commas are automatic.
class JsonWriter {
public:
    explicit JsonWriter(std::string& out) : out_(out) {}

    template <class F>
    void object(F&& body) {
        open('{');
        std::forward<F>(body)();
        close('}');
    }
    template <class F>
    void array(F&& body) {
        open('[');
        std::forward<F>(body)();
        close(']');
    }
    template <class Range, class F>
    void array_of(const Range& range, F&& each) {
        array([&] {
            for (const auto& item : range) each(item);
        });
    }

    JsonWriter& key(std::string_view k) {
        separate();
        out_ += '"';
        out_ += k;
        out_ += "\":";
        after_key_ = true;
        return *this;
    }

    template <class T>
    void value(const T& v) {
        if constexpr (std::is_same_v<T, bool>) {
            separate();
            out_ += v ? "true" : "false";
        } else if constexpr (std::is_same_v<T, std::nullptr_t>) {
            separate();
            out_ += "null";
        } else if constexpr (std::is_integral_v<T>) {
            separate();
            char buf[24];
            auto r = std::to_chars(buf, buf + sizeof buf, v);
            out_.append(buf, r.ptr);
        } else if constexpr (std::is_floating_point_v<T>) {
            separate();
            if (!std::isfinite(static_cast<double>(v))) {
                out_ += "null";
            } else {
                char buf[40];
                auto r = std::to_chars(buf, buf + sizeof buf, static_cast<double>(v));  // shortest round trip
                out_.append(buf, r.ptr);
            }
        } else if constexpr (std::is_same_v<T, RawJson>) {
            separate();
            out_ += v.text;
        } else if constexpr (std::is_same_v<T, Base58>) {
            separate();
            out_ += '"';
            append_base58(out_, v.bytes);
            out_ += '"';
        } else if constexpr (std::is_same_v<T, Base64>) {
            separate();
            out_ += '"';
            append_base64(out_, v.bytes);
            out_ += '"';
        } else if constexpr (is_optional<T>::value) {
            if (v) value(*v);
            else value(nullptr);
        } else {
            separate();
            append_json_string(out_, std::string_view(v));
        }
    }

    template <class T>
    void field(std::string_view k, const T& v) {
        key(k);
        value(v);
    }

private:
    template <class T>
    struct is_optional : std::false_type {};
    template <class T>
    struct is_optional<std::optional<T>> : std::true_type {};

    void separate() {
        if (after_key_) {
            after_key_ = false;
            return;
        }
        if (!first_.empty()) {
            if (!first_.back()) out_ += ',';
            first_.back() = false;
        }
    }
    void open(char c) {
        separate();
        out_ += c;
        first_.push_back(true);
    }
    void close(char c) {
        first_.pop_back();
        out_ += c;
    }

    std::string& out_;
    std::vector<bool> first_;
    bool after_key_ = false;
};

// ---- zstd.cpp --------------------------------------------------------------------
std::vector<std::uint8_t> zstd_decompress(Bytes input);

}  // namespace ob
