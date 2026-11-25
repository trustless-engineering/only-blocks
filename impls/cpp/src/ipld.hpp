// CARv1 sections, CIDs, DAG-CBOR and the Old Faithful IPLD node schemas (WIRE_FORMATS.md §3–7).
#pragma once

#include "onlyblocks.hpp"

namespace ob {

/// One DAG-CBOR data item. Tags are discarded, so a tag-42 link is just a byte string.
struct Cbor {
    enum class Type : std::uint8_t { Unsigned, Negative, Bytes, Text, Array, Map, False, True, Null, Float };
    Type type = Type::Null;
    std::uint64_t uint = 0;  ///< Unsigned value, or n for Negative (-1 - n)
    double real = 0;
    Bytes bytes;             ///< Bytes / Text payload
    std::vector<Cbor> items;  ///< Array items, or Map keys and values interleaved

    [[nodiscard]] const Cbor* at(std::size_t i) const {
        return type == Type::Array && i < items.size() ? &items[i] : nullptr;
    }
    [[nodiscard]] bool is_array() const { return type == Type::Array; }
    [[nodiscard]] bool is_bytes() const { return type == Type::Bytes; }
};

std::optional<std::uint64_t> as_u64(const Cbor* v);
std::optional<std::int64_t> as_i64(const Cbor* v);

/// Decodes exactly one item (trailing bytes are an error). Indefinite strings are kept in `arena`.
Cbor decode_cbor(Bytes in, Arena& arena);

/// A CID, as the raw bytes that key the CAR index.
struct Cid {
    std::string_view key;
    bool absent = false;  ///< identity hash of length 0 (bafkqaaa)
};

Cid parse_link(const Cbor* v);

/// Headerless CARv1 slice indexed by raw CID bytes, zero-copy over the slice.
class CarIndex {
public:
    CarIndex(Bytes slice, Arena& arena);
    [[nodiscard]] std::optional<Bytes> find(std::string_view cid) const;
    /// The node for `cid`, decoded and checked to be an array of the given kind.
    [[nodiscard]] Cbor node(std::string_view cid, std::uint64_t kind) const;
    [[nodiscard]] const std::optional<Bytes>& block() const { return block_; }
    [[nodiscard]] Arena& arena() const { return arena_; }

private:
    std::unordered_map<std::string_view, Bytes> sections_;
    std::optional<Bytes> block_;
    Arena& arena_;
};

const Cbor& require_kind(const Cbor& v, std::uint64_t kind);

struct DataFrame {
    std::optional<std::uint64_t> hash;
    Bytes data;
    std::vector<std::string_view> next;

    static DataFrame parse(const Cbor& v);
    /// Iterative DFS over `next` links with cycle detection, then the CRC-64/FNV-1a check.
    [[nodiscard]] Bytes reassemble(const CarIndex& car) const;
};

struct BlockNode {
    std::uint64_t slot = 0;
    std::vector<std::string_view> entries;
    std::uint64_t parent_slot = 0;
    std::optional<std::int64_t> block_time;
    std::optional<std::uint64_t> block_height;
    std::optional<std::string_view> rewards;

    static BlockNode parse(const Cbor& v);
};

}  // namespace ob
