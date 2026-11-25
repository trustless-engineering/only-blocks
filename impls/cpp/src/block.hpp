// The getBlock pipeline (SPEC §4.5) and its JSON serialization (WIRE_FORMATS.md §13–14).
#pragma once

#include "archive.hpp"

namespace ob {

enum class Encoding { Json, JsonParsed, Base64, Base58 };
enum class Details { Full, Accounts, Signatures, None };

struct BlockOptions {
    std::uint64_t slot = 0;
    Encoding encoding = Encoding::Json;
    Details details = Details::Full;
    bool rewards = true;
    std::optional<std::uint8_t> max_version;
};

/// Writes the result value; throws RpcError / DecodeError before or while writing.
void get_block(Archive& archive, const BlockOptions& options, JsonWriter& out);

}  // namespace ob
