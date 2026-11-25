// Strict RFC 8259 JSON parser that keeps number and string lexemes (ids echo byte for byte).
#pragma once

#include "onlyblocks.hpp"

namespace ob {

struct Json {
    enum class Kind : std::uint8_t { Null, False, True, Number, String, Array, Object };
    Kind kind = Kind::Null;
    std::string_view raw;  ///< source lexeme for numbers and strings
    std::string text;      ///< decoded string content
    std::vector<Json> items;                         ///< array elements
    std::vector<std::pair<std::string, Json>> members;  ///< object members, in source order

    [[nodiscard]] bool is(Kind k) const { return kind == k; }
    [[nodiscard]] bool is_string(std::string_view s) const { return kind == Kind::String && text == s; }
    /// Last occurrence of `key` (duplicate keys: last wins), or nullptr.
    [[nodiscard]] const Json* get(std::string_view key) const;
};

struct JsonParseError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

/// Parses a whole body; throws JsonParseError. Nesting is limited to 128 levels.
Json parse_json(std::string_view text);

}  // namespace ob
