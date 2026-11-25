// Hashes (constexpr tables), Base58/Base64, UTF-8 and number helpers.
#include "onlyblocks.hpp"

namespace ob {
namespace {

/// CRC-64/GO-ISO slicing-by-8 tables, computed entirely at compile time.
constexpr auto make_crc_tables() {
    std::array<std::array<std::uint64_t, 256>, 8> t{};
    for (std::uint64_t b = 0; b < 256; ++b) {
        std::uint64_t crc = b;
        for (int i = 0; i < 8; ++i) crc = (crc >> 1) ^ ((crc & 1) ? 0xD800000000000000ULL : 0);
        t[0][b] = crc;
    }
    for (std::size_t b = 0; b < 256; ++b)
        for (std::size_t k = 1; k < 8; ++k) t[k][b] = (t[k - 1][b] >> 8) ^ t[0][t[k - 1][b] & 0xFF];
    return t;
}
constexpr auto kCrc = make_crc_tables();

constexpr std::uint64_t crc64_bytewise(std::string_view s) {
    std::uint64_t crc = ~0ULL;
    for (char ch : s) crc = (crc >> 8) ^ kCrc[0][(crc ^ static_cast<std::uint8_t>(ch)) & 0xFF];
    return ~crc;
}
static_assert(crc64_bytewise("123456789") == 0xB90956C775A41001ULL, "CRC-64/GO-ISO check value");

constexpr std::string_view kBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr std::string_view kBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

constexpr std::uint64_t P1 = 0x9E3779B185EBCA87ULL, P2 = 0xC2B2AE3D27D4EB4FULL, P3 = 0x165667B19E3779F9ULL,
                        P4 = 0x85EBCA77C2B2AE63ULL, P5 = 0x27D4EB2F165667C5ULL;
constexpr std::uint64_t xround(std::uint64_t acc, std::uint64_t lane) { return std::rotl(acc + lane * P2, 31) * P1; }

}  // namespace

std::uint64_t crc64_go_iso(Bytes data) {
    std::uint64_t crc = ~0ULL;
    const std::uint8_t* p = data.data();
    std::size_t n = data.size();
    for (; n >= 8; p += 8, n -= 8) {
        crc ^= load_le<std::uint64_t>(p);
        crc = kCrc[7][crc & 0xFF] ^ kCrc[6][(crc >> 8) & 0xFF] ^ kCrc[5][(crc >> 16) & 0xFF] ^
              kCrc[4][(crc >> 24) & 0xFF] ^ kCrc[3][(crc >> 32) & 0xFF] ^ kCrc[2][(crc >> 40) & 0xFF] ^
              kCrc[1][(crc >> 48) & 0xFF] ^ kCrc[0][crc >> 56];
    }
    for (; n; --n) crc = (crc >> 8) ^ kCrc[0][(crc ^ *p++) & 0xFF];
    return ~crc;
}

std::uint64_t fnv1a64(Bytes data) {
    std::uint64_t h = 0xCBF29CE484222325ULL;
    for (auto b : data) h = (h ^ b) * 0x100000001B3ULL;
    return h;
}

std::uint64_t xxh64(Bytes data) {
    const std::uint8_t* p = data.data();
    std::size_t n = data.size(), i = 0;
    std::uint64_t h;
    if (n >= 32) {
        std::array<std::uint64_t, 4> v{P1 + P2, P2, 0, 0 - P1};
        for (; i + 32 <= n; i += 32)
            for (std::size_t j = 0; j < 4; ++j) v[j] = xround(v[j], load_le<std::uint64_t>(p + i + 8 * j));
        h = std::rotl(v[0], 1) + std::rotl(v[1], 7) + std::rotl(v[2], 12) + std::rotl(v[3], 18);
        for (auto lane : v) h = (h ^ xround(0, lane)) * P1 + P4;
    } else {
        h = P5;
    }
    h += n;
    for (; i + 8 <= n; i += 8) h = std::rotl(h ^ xround(0, load_le<std::uint64_t>(p + i)), 27) * P1 + P4;
    if (i + 4 <= n) {
        h = std::rotl(h ^ (load_le<std::uint32_t>(p + i) * P1), 23) * P2 + P3;
        i += 4;
    }
    for (; i < n; ++i) h = std::rotl(h ^ (p[i] * P5), 11) * P1;
    h ^= h >> 33;
    h *= P2;
    h ^= h >> 29;
    h *= P3;
    h ^= h >> 32;
    return h;
}

bool valid_utf8(Bytes data) {
    std::size_t i = 0, n = data.size();
    while (i < n) {
        auto b = data[i];
        if (b < 0x80) {
            ++i;
            continue;
        }
        std::size_t len;
        std::uint32_t cp;
        if (b >= 0xC2 && b <= 0xDF) len = 2, cp = b & 0x1F;
        else if (b >= 0xE0 && b <= 0xEF) len = 3, cp = b & 0x0F;
        else if (b >= 0xF0 && b <= 0xF4) len = 4, cp = b & 0x07;
        else return false;
        if (n - i < len) return false;
        for (std::size_t k = 1; k < len; ++k) {
            if ((data[i + k] & 0xC0) != 0x80) return false;
            cp = cp << 6 | (data[i + k] & 0x3F);
        }
        if ((len == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) || (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)))
            return false;
        i += len;
    }
    return true;
}

std::optional<std::uint64_t> parse_unsigned(std::string_view s, std::uint64_t max) {
    if (s.starts_with('+')) s.remove_prefix(1);
    if (s.empty()) return std::nullopt;
    std::uint64_t v = 0;
    for (char ch : s) {
        if (ch < '0' || ch > '9') return std::nullopt;
        auto d = static_cast<std::uint64_t>(ch - '0');
        if (v > (max - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}

std::string ui_amount_string(std::uint64_t amount, unsigned decimals) {
    std::string digits = std::to_string(amount);
    if (decimals == 0) return digits;
    if (digits.size() <= decimals) digits.insert(0, decimals - digits.size() + 1, '0');
    digits.insert(digits.size() - decimals, 1, '.');
    while (digits.back() == '0') digits.pop_back();
    if (digits.back() == '.') digits.pop_back();
    return digits;
}

/// Base58 with base-58^5 limbs (each below 656 356 768), five digits per limb.
void append_base58(std::string& out, Bytes data) {
    constexpr std::uint32_t kLimb = 656'356'768;  // 58^5
    std::size_t zeros = 0;
    while (zeros < data.size() && data[zeros] == 0) ++zeros;
    std::array<std::uint32_t, 24> small{};
    std::vector<std::uint32_t> large;
    std::span<std::uint32_t> limbs = small;
    if (std::size_t need = data.size() * 8 / 29 + 2; need > small.size()) {
        large.resize(need);
        limbs = large;
    }
    std::size_t used = 0;
    for (auto b : data.subspan(zeros)) {
        std::uint64_t carry = b;
        for (std::size_t j = 0; j < used; ++j) {
            carry += static_cast<std::uint64_t>(limbs[j]) << 8;
            limbs[j] = static_cast<std::uint32_t>(carry % kLimb);
            carry /= kLimb;
        }
        for (; carry; carry /= kLimb) limbs[used++] = static_cast<std::uint32_t>(carry % kLimb);
    }
    out.append(zeros, '1');
    for (std::size_t j = used; j-- > 0;) {
        std::array<char, 5> d{};
        for (std::uint32_t v = limbs[j], k = 5; k-- > 0; v /= 58) d[k] = kBase58[v % 58];
        std::size_t start = 0;
        if (j == used - 1)
            while (start < 4 && d[start] == '1') ++start;
        out.append(d.data() + start, d.size() - start);
    }
}

std::string base58(Bytes data) {
    std::string s;
    append_base58(s, data);
    return s;
}

void append_base64(std::string& out, Bytes data) {
    std::size_t i = 0, n = data.size();
    out.reserve(out.size() + (n + 2) / 3 * 4);
    for (; i + 3 <= n; i += 3) {
        std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16 | static_cast<std::uint32_t>(data[i + 1]) << 8 | data[i + 2];
        for (int s = 18; s >= 0; s -= 6) out += kBase64[(v >> s) & 63];
    }
    if (n - i == 1) {
        std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16;
        out += kBase64[v >> 18];
        out += kBase64[(v >> 12) & 63];
        out += "==";
    } else if (n - i == 2) {
        std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16 | static_cast<std::uint32_t>(data[i + 1]) << 8;
        out += kBase64[v >> 18];
        out += kBase64[(v >> 12) & 63];
        out += kBase64[(v >> 6) & 63];
        out += '=';
    }
}

void append_json_string(std::string& out, std::string_view s) {
    constexpr std::string_view hex = "0123456789abcdef";
    out += '"';
    std::size_t run = 0;
    for (std::size_t i = 0; i < s.size(); ++i) {
        auto ch = static_cast<unsigned char>(s[i]);
        if (ch >= 0x20 && ch != '"' && ch != '\\') continue;
        out.append(s.substr(run, i - run));
        run = i + 1;
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                out += "\\u00";
                out += hex[ch >> 4];
                out += hex[ch & 15];
        }
    }
    out.append(s.substr(run));
    out += '"';
}

}  // namespace ob
