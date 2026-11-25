// Solana VersionedTransaction and transaction-metadata / rewards model (WIRE_FORMATS.md §8–12).
#pragma once

#include "onlyblocks.hpp"

namespace ob {

struct CompiledInstruction {
    std::uint8_t program = 0;
    Bytes accounts, data;
};

struct AddressTableLookup {
    Bytes account_key, writable, readonly;
};

struct TransactionConfig {
    std::optional<std::uint64_t> priority_fee;
    std::optional<std::uint32_t> compute_unit_limit, loaded_accounts_data_size_limit, heap_size;
};

struct Transaction {
    std::optional<std::uint8_t> version;  ///< nullopt for legacy
    std::vector<Bytes> signatures;  ///< 64-byte views
    std::uint8_t num_required = 0, num_readonly_signed = 0, num_readonly_unsigned = 0;
    std::vector<Bytes> keys;  ///< static account keys, 32-byte views
    Bytes recent_blockhash;
    std::vector<CompiledInstruction> instructions;
    std::vector<AddressTableLookup> lookups;
    std::optional<TransactionConfig> config;
    Bytes raw;  ///< the consumed prefix (trailing bytes are not re-encoded)

    static Transaction parse(Bytes wire);
};

/// Bincode `TransactionError`; rendered to its reference JSON form on output.
struct TransactionError {
    std::uint32_t variant = 0;
    std::uint8_t index = 0;          ///< instruction / account index payloads
    std::uint32_t instruction = 0;   ///< InstructionError variant
    std::uint32_t custom = 0;        ///< Custom(u32)
    [[nodiscard]] std::string json() const;
};

struct Reward {
    std::string_view pubkey;
    std::int64_t lamports = 0;
    std::uint64_t post_balance = 0;
    std::optional<std::string_view> reward_type;
    std::optional<std::uint8_t> commission;
};

struct TokenBalance {
    std::uint8_t account_index = 0;
    std::string_view mint, owner, program_id, amount;
    std::optional<double> ui_amount;
    std::uint8_t decimals = 0;
    std::string ui_amount_string;
};

struct InnerInstruction {
    std::uint8_t program = 0;
    Bytes accounts, data;
    std::optional<std::uint32_t> stack_height;
};

struct InnerInstructions {
    std::uint8_t index = 0;
    std::vector<InnerInstruction> instructions;
};

struct ReturnData {
    Bytes program_id, data;
};

struct Meta {
    std::optional<TransactionError> err;
    std::uint64_t fee = 0;
    std::vector<std::uint64_t> pre_balances, post_balances;
    std::optional<std::vector<InnerInstructions>> inner_instructions;
    std::optional<std::vector<std::string_view>> log_messages;
    std::optional<std::vector<TokenBalance>> pre_token_balances, post_token_balances;
    std::optional<std::vector<Reward>> rewards;
    std::vector<Bytes> loaded_writable, loaded_readonly;
    std::optional<ReturnData> return_data;
    std::optional<std::uint64_t> compute_units_consumed, cost_units;
};

struct BlockRewards {
    std::vector<Reward> rewards;
    std::optional<std::uint64_t> partitions;
};

/// Metadata frame (§9): nullopt for an empty frame. Decoded buffers are kept in `arena`.
std::optional<Meta> decode_metadata(std::uint64_t slot, Bytes frame, Arena& arena);
BlockRewards decode_rewards(std::uint64_t slot, Bytes frame, Arena& arena);

}  // namespace ob
