#include "ipld.hpp"

#include <unordered_set>

namespace ob {
namespace {

constexpr std::size_t kMaxSection = 32 * kMiB;
constexpr int kMaxDepth = 128;

double half_to_double(std::uint16_t h) {
    int exp = (h >> 10) & 0x1F, mant = h & 0x3FF;
    double v = exp == 0    ? std::ldexp(mant, -24)
               : exp == 31 ? (mant ? std::numeric_limits<double>::quiet_NaN() : std::numeric_limits<double>::infinity())
                           : std::ldexp(mant + 1024, exp - 25);
    return (h & 0x8000) ? -v : v;
}

class CborDecoder {
public:
    CborDecoder(Bytes in, Arena& arena) : r_(in), arena_(arena) {}

    Cbor document() {
        Cbor v = item(0);
        require(r_.empty(), "trailing CBOR bytes");
        return v;
    }

private:
    /// The argument, or nullopt for the indefinite-length marker.
    std::optional<std::uint64_t> argument(int info) {
        if (info < 24) return static_cast<std::uint64_t>(info);
        switch (info) {
            case 24: return r_.be(1);
            case 25: return r_.be(2);
            case 26: return r_.be(4);
            case 27: return r_.be(8);
            case 31: return std::nullopt;
            default: fail("reserved CBOR additional info");
        }
    }

    bool at_break() {
        if (r_.peek() != 0xFF) return false;
        r_.u8();
        return true;
    }

    Cbor item(int depth) {
        require(depth <= kMaxDepth, "CBOR nesting limit exceeded");
        auto head = r_.u8();
        int major = head >> 5, info = head & 31;
        Cbor v;
        if (major == 7) {
            switch (info) {
                case 20: v.type = Cbor::Type::False; break;
                case 21: v.type = Cbor::Type::True; break;
                case 22:
                case 23: v.type = Cbor::Type::Null; break;
                case 25: v.type = Cbor::Type::Float, v.real = half_to_double(static_cast<std::uint16_t>(r_.be(2))); break;
                case 26: v.type = Cbor::Type::Float, v.real = std::bit_cast<float>(static_cast<std::uint32_t>(r_.be(4))); break;
                case 27: v.type = Cbor::Type::Float, v.real = std::bit_cast<double>(r_.be(8)); break;
                default: fail("unsupported CBOR simple value");
            }
            return v;
        }
        auto arg = argument(info);
        switch (major) {
            case 0: v.type = Cbor::Type::Unsigned, v.uint = arg.value(); return v;
            case 1: v.type = Cbor::Type::Negative, v.uint = arg.value(); return v;
            case 2:
            case 3: {
                v.type = major == 2 ? Cbor::Type::Bytes : Cbor::Type::Text;
                if (arg) {
                    v.bytes = r_.take(*arg);
                } else {
                    std::vector<std::uint8_t> joined;
                    while (!at_break()) {
                        auto chunk = r_.u8();
                        require(chunk >> 5 == major && (chunk & 31) != 31, "invalid CBOR string chunk");
                        auto part = r_.take(argument(chunk & 31).value());
                        require(major == 2 || valid_utf8(part), "invalid UTF-8 in CBOR text");
                        joined.insert(joined.end(), part.begin(), part.end());
                    }
                    v.bytes = arena_.keep(std::move(joined));
                }
                require(major == 2 || valid_utf8(v.bytes), "invalid UTF-8 in CBOR text");
                return v;
            }
            case 4:
            case 5: {
                v.type = major == 4 ? Cbor::Type::Array : Cbor::Type::Map;
                std::size_t per = major == 4 ? 1 : 2;
                if (arg) {
                    require(*arg <= r_.remaining() / per, "CBOR count exceeds input");
                    v.items.reserve(static_cast<std::size_t>(*arg) * per);
                    for (std::uint64_t i = 0; i < *arg * per; ++i) v.items.push_back(item(depth + 1));
                } else {
                    while (!at_break())
                        for (std::size_t k = 0; k < per; ++k) v.items.push_back(item(depth + 1));
                }
                return v;
            }
            case 6: return item(depth + 1);  // tags are discarded
            default: fail("invalid CBOR major type");
        }
    }

    Reader r_;
    Arena& arena_;
};

/// Parses a CID at the start of `r`; returns whether it is the empty identity CID.
bool read_cid(Reader& r) {
    auto a = r.uvarint();
    auto b = r.uvarint();
    if (a == 0x12 && b == 0x20) {
        r.take(32);  // CIDv0: bare sha2-256 multihash
        return false;
    }
    require(a != 0, "explicit CIDv0 is not supported");
    require(a == 1, "unsupported CID version");
    auto hash_code = r.uvarint();
    auto hash_len = r.uvarint();
    require(hash_len <= 64, "CID digest too long");
    r.take(hash_len);
    return hash_code == 0 && hash_len == 0;
}

bool is_car_header(Bytes section, Arena& arena) {
    if ((section[0] & 0xE0) != 0xA0) return false;
    try {
        auto v = decode_cbor(section, arena);
        if (v.type != Cbor::Type::Map) return false;
        for (std::size_t i = 0; i < v.items.size(); i += 2)
            if (v.items[i].type == Cbor::Type::Text && as_chars(v.items[i].bytes) == "version") return true;
    } catch (const DecodeError&) {
    }
    return false;
}

bool looks_like_block(Bytes node) {
    if (node.empty() || node[0] >> 5 != 4) return false;
    int info = node[0] & 31;
    std::size_t header = info < 24 || info == 31 ? 1 : info == 24 ? 2 : info == 25 ? 3 : info == 26 ? 5 : info == 27 ? 9 : 0;
    return header && header < node.size() && node[header] == 0x02;
}

std::vector<std::string_view> links(const Cbor* list) {
    std::vector<std::string_view> out;
    if (list && list->is_array()) {
        out.reserve(list->items.size());
        for (const auto& item : list->items) out.push_back(parse_link(&item).key);
    }
    return out;
}

void verify_hash(Bytes data, std::uint64_t expected) {
    require(crc64_go_iso(data) == expected || fnv1a64(data) == expected, "DataFrame hash mismatch");
}

}  // namespace

Cbor decode_cbor(Bytes in, Arena& arena) { return CborDecoder(in, arena).document(); }

std::optional<std::uint64_t> as_u64(const Cbor* v) {
    if (v && v->type == Cbor::Type::Unsigned) return v->uint;
    return std::nullopt;
}

std::optional<std::int64_t> as_i64(const Cbor* v) {
    constexpr auto kMax = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (v && v->type == Cbor::Type::Unsigned && v->uint <= kMax) return static_cast<std::int64_t>(v->uint);
    if (v && v->type == Cbor::Type::Negative && v->uint <= kMax) return -1 - static_cast<std::int64_t>(v->uint);
    return std::nullopt;
}

Cid parse_link(const Cbor* v) {
    require(v && v->is_bytes() && !v->bytes.empty() && v->bytes[0] == 0, "invalid CID link");
    Reader r(v->bytes.subspan(1));
    bool absent = read_cid(r);  // trailing bytes after the CID are ignored
    return {as_chars(r.consumed()), absent};
}

CarIndex::CarIndex(Bytes slice, Arena& arena) : arena_(arena) {
    Reader r(slice);
    bool first = true;
    while (!r.empty()) {
        auto len = r.uvarint();
        if (len == 0) continue;
        require(len <= kMaxSection, "oversize CAR section");
        auto section = r.take(len);
        if (std::exchange(first, false) && is_car_header(section, arena)) continue;
        Reader s(section);
        read_cid(s);
        auto node = section.subspan(s.pos());
        sections_.insert_or_assign(as_chars(section.first(s.pos())), node);
        if (looks_like_block(node)) block_ = node;  // the last Block-shaped section wins
    }
}

std::optional<Bytes> CarIndex::find(std::string_view cid) const {
    if (auto it = sections_.find(cid); it != sections_.end()) return it->second;
    return std::nullopt;
}

Cbor CarIndex::node(std::string_view cid, std::uint64_t kind) const {
    auto bytes = find(cid);
    require(bytes.has_value(), "CID missing from CAR slice");
    Cbor v = decode_cbor(*bytes, arena_);
    require_kind(v, kind);
    return v;
}

const Cbor& require_kind(const Cbor& v, std::uint64_t kind) {
    if (!v.is_array() || as_u64(v.at(0)) != kind) fail(std::format("expected IPLD node kind {}", kind));
    return v;
}

DataFrame DataFrame::parse(const Cbor& v) {
    require_kind(v, 6);
    DataFrame f;
    f.hash = as_u64(v.at(1));
    if (const auto* data = v.at(4); data && data->is_bytes()) f.data = data->bytes;
    if (const auto* next = v.at(5); next && next->is_array() && !next->items.empty()) f.next = links(next);
    return f;
}

Bytes DataFrame::reassemble(const CarIndex& car) const {
    if (next.empty()) {
        if (hash) verify_hash(data, *hash);
        return data;
    }
    std::vector<std::uint8_t> out(data.begin(), data.end());
    std::unordered_set<std::string_view> visited;
    std::vector<std::string_view> stack(next.rbegin(), next.rend());
    while (!stack.empty()) {
        auto cid = stack.back();
        stack.pop_back();
        require(visited.insert(cid).second, "cyclic DataFrame");
        auto frame = DataFrame::parse(car.node(cid, 6));
        out.insert(out.end(), frame.data.begin(), frame.data.end());
        stack.insert(stack.end(), frame.next.rbegin(), frame.next.rend());
    }
    Bytes joined = car.arena().keep(std::move(out));
    if (hash) verify_hash(joined, *hash);
    return joined;
}

BlockNode BlockNode::parse(const Cbor& v) {
    require_kind(v, 2);
    BlockNode b;
    auto slot = as_u64(v.at(1));
    require(slot.has_value(), "Block node has no slot");
    b.slot = *slot;
    b.entries = links(v.at(3));
    if (const auto* meta = v.at(4); meta && meta->is_array()) {
        b.parent_slot = as_u64(meta->at(0)).value_or(0);
        if (auto t = as_i64(meta->at(1)); t && *t != 0) b.block_time = t;  // blocktime 0 is reported as null
        b.block_height = as_u64(meta->at(2));
    }
    if (const auto* rewards = v.at(5); rewards && rewards->is_bytes()) {
        auto cid = parse_link(rewards);
        if (!cid.absent) b.rewards = cid.key;
    }
    return b;
}

}  // namespace ob
