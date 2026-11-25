#include "solana.hpp"

namespace ob {
namespace {

constexpr std::array<std::string_view, 54> kInstructionErrors{
    "GenericError", "InvalidArgument", "InvalidInstructionData", "InvalidAccountData", "AccountDataTooSmall",
    "InsufficientFunds", "IncorrectProgramId", "MissingRequiredSignature", "AccountAlreadyInitialized",
    "UninitializedAccount", "UnbalancedInstruction", "ModifiedProgramId", "ExternalAccountLamportSpend",
    "ExternalAccountDataModified", "ReadonlyLamportChange", "ReadonlyDataModified", "DuplicateAccountIndex",
    "ExecutableModified", "RentEpochModified", "NotEnoughAccountKeys", "AccountDataSizeChanged",
    "AccountNotExecutable", "AccountBorrowFailed", "AccountBorrowOutstanding", "DuplicateAccountOutOfSync", "Custom",
    "InvalidError", "ExecutableDataModified", "ExecutableLamportChange", "ExecutableAccountNotRentExempt",
    "UnsupportedProgramId", "CallDepth", "MissingAccount", "ReentrancyNotAllowed", "MaxSeedLengthExceeded",
    "InvalidSeeds", "InvalidRealloc", "ComputationalBudgetExceeded", "PrivilegeEscalation",
    "ProgramEnvironmentSetupFailure", "ProgramFailedToComplete", "ProgramFailedToCompile", "Immutable",
    "IncorrectAuthority", "BorshIoError", "AccountNotRentExempt", "InvalidAccountOwner", "ArithmeticOverflow",
    "UnsupportedSysvar", "IllegalOwner", "MaxAccountsDataAllocationsExceeded", "MaxAccountsExceeded",
    "MaxInstructionTraceLengthExceeded", "BuiltinProgramsMustConsumeComputeUnits"};

constexpr std::array<std::string_view, 39> kTransactionErrors{
    "AccountInUse", "AccountLoadedTwice", "AccountNotFound", "ProgramAccountNotFound", "InsufficientFundsForFee",
    "InvalidAccountForFee", "AlreadyProcessed", "BlockhashNotFound", "InstructionError", "CallChainTooDeep",
    "MissingSignatureForFee", "InvalidAccountIndex", "SignatureFailure", "InvalidProgramForExecution",
    "SanitizeFailure", "ClusterMaintenance", "AccountBorrowOutstanding", "WouldExceedMaxBlockCostLimit",
    "UnsupportedVersion", "InvalidWritableAccount", "WouldExceedMaxAccountCostLimit",
    "WouldExceedAccountDataBlockLimit", "TooManyAccountLocks", "AddressLookupTableNotFound",
    "InvalidAddressLookupTableOwner", "InvalidAddressLookupTableData", "InvalidAddressLookupTableIndex",
    "InvalidRentPayingAccount", "WouldExceedMaxVoteCostLimit", "WouldExceedAccountDataTotalLimit",
    "DuplicateInstruction", "InsufficientFundsForRent", "MaxLoadedAccountsDataSizeExceeded",
    "InvalidLoadedAccountsDataSizeLimit", "ResanitizationNeeded", "ProgramExecutionTemporarilyRestricted",
    "UnbalancedTransaction", "ProgramCacheHitMaxLimit", "CommitCancelled"};

constexpr std::array<std::string_view, 4> kRewardTypes{"Fee", "Rent", "Staking", "Voting"};

// ================================================================ bincode

/// A fixed-width read ran out of input: the only error bincode's `default_on_eof` absorbs.
struct BincodeEof {};

class Bincode {
public:
    explicit Bincode(Bytes b) : data_(b) {}
    [[nodiscard]] bool empty() const { return pos_ == data_.size(); }

    Bytes fixed(std::size_t n) {
        if (n > data_.size() - pos_) throw BincodeEof{};  // consumes nothing
        auto out = data_.subspan(pos_, n);
        pos_ += n;
        return out;
    }
    std::uint8_t u8() { return fixed(1)[0]; }
    std::uint32_t u32() { return load_le<std::uint32_t>(fixed(4).data()); }
    std::uint64_t u64() { return load_le<std::uint64_t>(fixed(8).data()); }
    double f64() { return std::bit_cast<double>(u64()); }

    std::string_view string() {
        auto n = u64();
        require(n <= data_.size() - pos_, "bincode string exceeds input");  // not an EOF
        auto bytes = data_.subspan(pos_, static_cast<std::size_t>(n));
        require(valid_utf8(bytes), "bincode string is not UTF-8");
        pos_ += static_cast<std::size_t>(n);
        return as_chars(bytes);
    }

    /// short_vec<u8>: one fixed read per element, so a shortfall consumes the rest, then EOFs.
    Bytes short_bytes() {
        auto n = compact_u16();
        if (n > data_.size() - pos_) {
            pos_ = data_.size();
            throw BincodeEof{};
        }
        return fixed(n);
    }

    /// Vec<u8> as a sequence: same shortfall behaviour as short_bytes.
    Bytes byte_seq() {
        auto n = u64();
        if (n > data_.size() - pos_) {
            pos_ = data_.size();
            throw BincodeEof{};
        }
        return fixed(static_cast<std::size_t>(n));
    }

    template <class F>
    auto option(F&& read) -> std::optional<decltype(read())> {
        switch (u8()) {
            case 0: return std::nullopt;
            case 1: return read();
            default: fail("invalid bincode Option tag");
        }
    }

    template <class F>
    auto vec(F&& read) -> std::vector<decltype(read())> {
        auto n = u64();
        std::vector<decltype(read())> out;
        out.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(n, (data_.size() - pos_) / 1 + 1)));
        for (std::uint64_t i = 0; i < n; ++i) out.push_back(read());
        return out;
    }

    TransactionError transaction_error() {
        TransactionError e;
        e.variant = u32();
        require(e.variant < kTransactionErrors.size(), "invalid TransactionError variant");
        if (e.variant == 8) {
            e.index = u8();
            e.instruction = u32();
            require(e.instruction < kInstructionErrors.size(), "invalid InstructionError variant");
            if (e.instruction == 25) e.custom = u32();
        } else if (e.variant == 30 || e.variant == 31 || e.variant == 35) {
            e.index = u8();
        }
        return e;
    }

private:
    std::size_t compact_u16() {
        std::uint32_t v = 0;
        for (int k = 0; k < 3; ++k) {
            auto b = u8();
            require(k == 0 || b != 0, "non-canonical short_vec length");
            v |= static_cast<std::uint32_t>(b & 0x7F) << (7 * k);
            if (!(b & 0x80)) {
                require(v <= 0xFFFF, "short_vec length overflow");
                return v;
            }
        }
        fail("short_vec length continues past three bytes");
    }

    Bytes data_;
    std::size_t pos_ = 0;
};

/// An `eof` field: a fixed-width EOF anywhere inside it yields the default value.
template <class F>
auto eof_default(F&& read) -> decltype(read()) {
    try {
        return read();
    } catch (const BincodeEof&) {
        return {};
    }
}

enum class TokenLayout { V1, V2, Stored };

TokenBalance bincode_token(Bincode& r, TokenLayout layout) {
    TokenBalance t;
    t.account_index = r.u8();
    t.mint = r.string();
    t.ui_amount = r.f64();  // the bincode path always reports uiAmount, even 0.0
    t.decimals = r.u8();
    t.amount = r.string();
    if (layout == TokenLayout::V2) {
        t.owner = r.string();
    } else if (layout == TokenLayout::Stored) {
        t.owner = eof_default([&] { return r.string(); });
        t.program_id = eof_default([&] { return r.string(); });
    }
    t.ui_amount_string = ui_amount_string(parse_unsigned(t.amount, UINT64_MAX).value_or(0), t.decimals);
    return t;
}

Reward bincode_reward(Bincode& r, bool extended) {
    Reward w;
    w.pubkey = r.string();
    w.lamports = static_cast<std::int64_t>(r.u64());
    auto reward_type = [&]() -> std::optional<std::string_view> {
        auto t = r.option([&] {
            auto v = r.u32();
            require(v < 4, "invalid RewardType variant");
            return kRewardTypes[v];
        });
        return t ? std::optional<std::string_view>(*t) : std::nullopt;
    };
    if (extended) {
        w.post_balance = eof_default([&] { return r.u64(); });
        w.reward_type = eof_default(reward_type);
        w.commission = eof_default([&] { return r.option([&] { return r.u8(); }); });
    } else {
        w.post_balance = r.u64();
        w.reward_type = reward_type();
    }
    return w;
}

Meta bincode_meta(Bincode& r, bool legacy_inner, TokenLayout tokens) {
    Meta m;
    switch (r.u32()) {
        case 0: break;
        case 1: m.err = r.transaction_error(); break;
        default: fail("invalid bincode Result tag");
    }
    m.fee = r.u64();
    m.pre_balances = r.vec([&] { return r.u64(); });
    m.post_balances = r.vec([&] { return r.u64(); });
    m.inner_instructions = eof_default([&] {
        return r.option([&] {
            return r.vec([&] {
                InnerInstructions group;
                group.index = r.u8();
                group.instructions = r.vec([&] {
                    InnerInstruction ix;
                    ix.program = r.u8();
                    ix.accounts = r.short_bytes();
                    ix.data = r.short_bytes();
                    if (!legacy_inner) ix.stack_height = r.option([&] { return r.u32(); });
                    return ix;
                });
                return group;
            });
        });
    });
    m.log_messages = eof_default([&] { return r.option([&] { return r.vec([&] { return r.string(); }); }); });
    auto token_list = [&] { return r.option([&] { return r.vec([&] { return bincode_token(r, tokens); }); }); };
    m.pre_token_balances = eof_default(token_list);
    m.post_token_balances = eof_default(token_list);
    m.rewards = eof_default([&] { return r.option([&] { return r.vec([&] { return bincode_reward(r, true); }); }); });
    m.return_data = eof_default([&] {
        return r.option([&] {
            ReturnData rd;
            rd.program_id = r.fixed(32);
            rd.data = r.byte_seq();
            return rd;
        });
    });
    m.compute_units_consumed = eof_default([&] { return r.option([&] { return r.u64(); }); });
    m.cost_units = eof_default([&] { return r.option([&] { return r.u64(); }); });
    return m;
}

/// Runs `read` over `bytes`; strict mode also requires every byte to be consumed.
template <class F>
auto try_bincode(Bytes bytes, bool strict, F&& read) -> std::optional<decltype(read(std::declval<Bincode&>()))> {
    try {
        Bincode r(bytes);
        auto v = read(r);
        if (strict && !r.empty()) return std::nullopt;
        return v;
    } catch (const BincodeEof&) {
    } catch (const DecodeError&) {
    }
    return std::nullopt;
}

Meta bincode_metadata(Bytes b) {
    using enum TokenLayout;
    constexpr std::array<std::pair<bool, TokenLayout>, 4> kLayouts{{{false, Stored}, {true, V1}, {true, V2}, {true, Stored}}};
    for (auto [legacy, tokens] : kLayouts)
        if (auto m = try_bincode(b, true, [&](Bincode& r) { return bincode_meta(r, legacy, tokens); })) return std::move(*m);
    if (auto m = try_bincode(b, false, [](Bincode& r) { return bincode_meta(r, false, Stored); })) return std::move(*m);
    fail("metadata is not valid bincode");
}

std::vector<Reward> bincode_rewards(Bytes b) {
    auto list = [](bool extended) {
        return [extended](Bincode& r) { return r.vec([&] { return bincode_reward(r, extended); }); };
    };
    if (auto v = try_bincode(b, true, list(true))) return std::move(*v);
    if (auto v = try_bincode(b, true, list(false))) return std::move(*v);
    if (auto v = try_bincode(b, false, list(true))) return std::move(*v);
    fail("rewards are not valid bincode");
}

// ================================================================ protobuf

/// Field cursor with prost semantics: unknown fields are skipped, known fields must match their wire type.
class Proto {
public:
    explicit Proto(Bytes b) : r_(b) {}

    struct Field {
        std::uint32_t number;
        int wire;
    };

    std::optional<Field> next() {
        if (r_.empty()) return std::nullopt;
        auto key = r_.uvarint();
        require(key <= 0xFFFFFFFFu, "protobuf: invalid key");
        Field f{static_cast<std::uint32_t>(key >> 3), static_cast<int>(key & 7)};
        require(f.wire <= 5, "protobuf: invalid wire type");
        require(f.number != 0, "protobuf: invalid tag 0");
        return f;
    }

    std::uint64_t varint(const Field& f) {
        expect(f, 0);
        return r_.uvarint();
    }
    bool boolean(const Field& f) { return varint(f) != 0; }
    Bytes bytes(const Field& f) {
        expect(f, 2);
        return r_.take(r_.uvarint());
    }
    std::string_view string(const Field& f) {
        auto b = bytes(f);
        require(valid_utf8(b), "protobuf: invalid UTF-8 string");
        return as_chars(b);
    }
    double f64(const Field& f) {
        expect(f, 1);
        return std::bit_cast<double>(r_.le<std::uint64_t>());
    }
    Proto message(const Field& f) { return Proto(bytes(f)); }

    /// repeated uint64: packed and unpacked encodings, freely mixed.
    void repeated_u64(const Field& f, std::vector<std::uint64_t>& out) {
        if (f.wire == 0) {
            out.push_back(r_.uvarint());
        } else {
            Reader packed(bytes(f));
            while (!packed.empty()) out.push_back(packed.uvarint());
        }
    }

    void skip(const Field& f, int depth = 0) {
        switch (f.wire) {
            case 0: r_.uvarint(); return;
            case 1: r_.take(8); return;
            case 2: r_.take(r_.uvarint()); return;
            case 5: r_.take(4); return;
            case 3:
                require(depth < 100, "protobuf: group nesting too deep");
                for (;;) {
                    auto inner = next();
                    require(inner.has_value(), "protobuf: unterminated group");
                    if (inner->wire == 4) {
                        require(inner->number == f.number, "protobuf: mismatched end group");
                        return;
                    }
                    skip(*inner, depth + 1);
                }
            default: fail("protobuf: unexpected end group");
        }
    }

private:
    static void expect(const Field& f, int wire) { require(f.wire == wire, "protobuf: wrong wire type for a known field"); }
    Reader r_;
};

/// Reward (in metadata and in block Rewards), converted as soon as its message ends (§10.3).
Reward proto_reward(Proto p) {
    Reward w;
    std::string_view commission, bps;
    std::uint64_t type = 0;
    while (auto f = p.next()) {
        switch (f->number) {
            case 1: w.pubkey = p.string(*f); break;
            case 2: w.lamports = static_cast<std::int64_t>(p.varint(*f)); break;
            case 3: w.post_balance = p.varint(*f); break;
            case 4: type = p.varint(*f); break;
            case 5: commission = p.string(*f); break;
            case 6: bps = p.string(*f); break;
            default: p.skip(*f);
        }
    }
    auto t = static_cast<std::int32_t>(static_cast<std::uint32_t>(type));
    if (t >= 1 && t <= 4) w.reward_type = kRewardTypes[static_cast<std::size_t>(t - 1)];
    if (auto c = parse_unsigned(commission, 255)) w.commission = static_cast<std::uint8_t>(*c);
    else if (auto b = parse_unsigned(bps, 65535); b && *b / 100 <= 255) w.commission = static_cast<std::uint8_t>(*b / 100);
    return w;
}

TokenBalance proto_token(Proto p) {
    TokenBalance t;
    std::uint64_t account_index = 0, decimals = 0;
    double ui = 0;
    std::string_view ui_string;
    while (auto f = p.next()) {
        switch (f->number) {
            case 1: account_index = p.varint(*f); break;
            case 2: t.mint = p.string(*f); break;
            case 3: {  // UiTokenAmount; repeated occurrences merge field by field
                auto a = p.message(*f);
                while (auto g = a.next()) {
                    switch (g->number) {
                        case 1: ui = a.f64(*g); break;
                        case 2: decimals = a.varint(*g); break;
                        case 3: t.amount = a.string(*g); break;
                        case 4: ui_string = a.string(*g); break;
                        default: a.skip(*g);
                    }
                }
                break;
            }
            case 4: t.owner = p.string(*f); break;
            case 5: t.program_id = p.string(*f); break;
            default: p.skip(*f);
        }
    }
    t.account_index = static_cast<std::uint8_t>(account_index);
    t.decimals = static_cast<std::uint8_t>(decimals);
    if (std::abs(ui) > std::numeric_limits<double>::epsilon()) t.ui_amount = ui;
    t.ui_amount_string = ui_string.empty()
                             ? ui_amount_string(parse_unsigned(t.amount, UINT64_MAX).value_or(0), t.decimals)
                             : std::string(ui_string);
    return t;
}

InnerInstructions proto_inner(Proto p) {
    InnerInstructions group;
    std::uint64_t index = 0;
    while (auto f = p.next()) {
        if (f->number == 1) {
            index = p.varint(*f);
        } else if (f->number == 2) {
            auto q = p.message(*f);
            InnerInstruction ix;
            std::uint64_t program = 0;
            while (auto g = q.next()) {
                switch (g->number) {
                    case 1: program = q.varint(*g); break;
                    case 2: ix.accounts = q.bytes(*g); break;
                    case 3: ix.data = q.bytes(*g); break;
                    case 4: ix.stack_height = static_cast<std::uint32_t>(q.varint(*g)); break;
                    default: q.skip(*g);
                }
            }
            ix.program = static_cast<std::uint8_t>(program);
            group.instructions.push_back(ix);
        } else {
            p.skip(*f);
        }
    }
    group.index = static_cast<std::uint8_t>(index);
    return group;
}

/// The wire-level TransactionStatusMeta, before the fallible conversion steps.
struct ProtoMeta {
    Meta meta;
    std::optional<Bytes> err;
    std::vector<Bytes> writable, readonly;
    std::optional<std::pair<Bytes, Bytes>> return_data;
    bool inner_none = false, logs_none = false, return_none = false;
    std::vector<InnerInstructions> inner;
    std::vector<std::string_view> logs;
    std::vector<TokenBalance> pre_tokens, post_tokens;
    std::vector<Reward> rewards;
};

ProtoMeta parse_proto_meta(Bytes b) {
    ProtoMeta pm;
    Proto p(b);
    while (auto f = p.next()) {
        switch (f->number) {
            case 1: {  // TransactionError { bytes err = 1 }
                auto e = p.message(*f);
                if (!pm.err) pm.err = Bytes{};
                while (auto g = e.next()) {
                    if (g->number == 1) pm.err = e.bytes(*g);
                    else e.skip(*g);
                }
                break;
            }
            case 2: pm.meta.fee = p.varint(*f); break;
            case 3: p.repeated_u64(*f, pm.meta.pre_balances); break;
            case 4: p.repeated_u64(*f, pm.meta.post_balances); break;
            case 5: pm.inner.push_back(proto_inner(p.message(*f))); break;
            case 6: pm.logs.push_back(p.string(*f)); break;
            case 7: pm.pre_tokens.push_back(proto_token(p.message(*f))); break;
            case 8: pm.post_tokens.push_back(proto_token(p.message(*f))); break;
            case 9: pm.rewards.push_back(proto_reward(p.message(*f))); break;
            case 10: pm.inner_none = p.boolean(*f); break;
            case 11: pm.logs_none = p.boolean(*f); break;
            case 12: pm.writable.push_back(p.bytes(*f)); break;
            case 13: pm.readonly.push_back(p.bytes(*f)); break;
            case 14: {  // ReturnData, merged field by field
                auto rd = p.message(*f);
                if (!pm.return_data) pm.return_data.emplace();
                while (auto g = rd.next()) {
                    if (g->number == 1) pm.return_data->first = rd.bytes(*g);
                    else if (g->number == 2) pm.return_data->second = rd.bytes(*g);
                    else rd.skip(*g);
                }
                break;
            }
            case 15: pm.return_none = p.boolean(*f); break;
            case 16: pm.meta.compute_units_consumed = p.varint(*f); break;
            case 17: pm.meta.cost_units = p.varint(*f); break;
            default: p.skip(*f);
        }
    }
    return pm;
}

/// §10.3: the conversion's own errors are final (no bincode fallback).
Meta convert(ProtoMeta pm) {
    Meta& m = pm.meta;
    if (pm.err) {
        try {
            Bincode r(*pm.err);
            m.err = r.transaction_error();  // trailing bytes allowed
        } catch (const BincodeEof&) {
            fail("truncated TransactionError in protobuf metadata");
        }
    }
    if (!pm.inner_none) m.inner_instructions = std::move(pm.inner);
    if (!pm.logs_none) m.log_messages = std::move(pm.logs);
    m.pre_token_balances = std::move(pm.pre_tokens);
    m.post_token_balances = std::move(pm.post_tokens);
    m.rewards = std::move(pm.rewards);
    for (auto [from, to] : {std::pair{&pm.writable, &m.loaded_writable}, std::pair{&pm.readonly, &m.loaded_readonly}})
        for (auto key : *from) {
            require(key.size() == 32, "loaded address is not 32 bytes");
            to->push_back(key);
        }
    if (!pm.return_none && pm.return_data) {
        require(pm.return_data->first.size() == 32, "return data program id is not 32 bytes");
        m.return_data = ReturnData{pm.return_data->first, pm.return_data->second};
    }
    return std::move(m);
}

BlockRewards parse_proto_rewards(Bytes b) {
    BlockRewards out;
    Proto p(b);
    while (auto f = p.next()) {
        if (f->number == 1) {
            out.rewards.push_back(proto_reward(p.message(*f)));
        } else if (f->number == 2) {
            auto n = p.message(*f);
            if (!out.partitions) out.partitions = 0;
            while (auto g = n.next()) {
                if (g->number == 1) out.partitions = n.varint(*g);
                else n.skip(*g);
            }
        } else {
            p.skip(*f);
        }
    }
    return out;
}

// ================================================================ frames (§9)

template <class Decode>
auto unwrap_frame(Bytes frame, Arena& arena, Decode&& decode) -> decltype(decode(frame)) {
    auto inflate = [&]() -> std::optional<Bytes> {
        try {
            return arena.keep(zstd_decompress(frame));
        } catch (const DecodeError&) {
            return std::nullopt;
        }
    };
    if (frame.size() >= 4 && load_le<std::uint32_t>(frame.data()) == 0xFD2FB528u) {
        if (auto plain = inflate()) return decode(*plain);  // its errors propagate
        return decode(frame);
    }
    try {
        return decode(frame);
    } catch (const DecodeError&) {
        auto plain = inflate();
        if (!plain) throw;  // the first failure
        return decode(*plain);
    }
}

}  // namespace

std::string TransactionError::json() const {
    auto name = kTransactionErrors.at(variant);
    switch (variant) {
        case 8:
            if (instruction == 25) return std::format(R"({{"InstructionError":[{},{{"Custom":{}}}]}})", index, custom);
            return std::format(R"({{"InstructionError":[{},"{}"]}})", index, kInstructionErrors.at(instruction));
        case 30: return std::format(R"({{"DuplicateInstruction":{}}})", index);
        case 31:
        case 35: return std::format(R"({{"{}":{{"account_index":{}}}}})", name, index);
        default: return std::format(R"("{}")", name);
    }
}

Transaction Transaction::parse(Bytes wire) {
    Reader r(wire);
    const auto discriminator = r.u8();
    auto read_list = [&](std::size_t n, std::size_t min_size, auto&& read) {
        require(n <= r.remaining() / min_size, "count exceeds input");
        std::vector<decltype(read())> out;
        out.reserve(n);
        for (std::size_t i = 0; i < n; ++i) out.push_back(read());
        return out;
    };
    auto read_signatures = [&](std::size_t n) { return read_list(n, 64, [&] { return r.take(64); }); };
    auto read_keys = [&](std::size_t n) { return read_list(n, 32, [&] { return r.take(32); }); };

    Transaction tx;
    if (discriminator == 0x81) {
        tx.version = 1;
        tx.num_required = r.u8();
        tx.num_readonly_signed = r.u8();
        tx.num_readonly_unsigned = r.u8();
        const auto mask = r.le<std::uint32_t>();
        require(!(mask & ~0x1fu) && ((mask & 3) == 0 || (mask & 3) == 3), "invalid v1 transaction config mask");
        tx.recent_blockhash = r.take(32);
        const auto instruction_count = r.u8();
        tx.keys = read_keys(r.u8());
        auto& config = tx.config.emplace();
        if (mask & 3) config.priority_fee = r.le<std::uint64_t>();
        if (mask & 4) config.compute_unit_limit = r.le<std::uint32_t>();
        if (mask & 8) config.loaded_accounts_data_size_limit = r.le<std::uint32_t>();
        if (mask & 16) config.heap_size = r.le<std::uint32_t>();

        Reader headers(r.take(static_cast<std::size_t>(instruction_count) * 4));
        tx.instructions.reserve(instruction_count);
        while (!headers.empty()) {
            const auto program = headers.u8();
            const auto account_count = headers.u8();
            const auto data_len = headers.le<std::uint16_t>();
            tx.instructions.push_back({program, r.take(account_count), r.take(data_len)});
        }
        tx.signatures = read_signatures(tx.num_required);
        tx.raw = r.consumed();
        return tx;
    }
    require(discriminator < 0x80, "invalid transaction discriminator");

    auto compact_u16 = [&] {
        std::uint32_t v = 0;
        for (int k = 0; k < 3; ++k) {
            auto b = r.u8();
            require(k == 0 || b != 0, "non-canonical compact-u16");
            v |= static_cast<std::uint32_t>(b & 0x7F) << (7 * k);
            if (!(b & 0x80)) {
                require(v <= 0xFFFF, "compact-u16 overflow");
                return static_cast<std::size_t>(v);
            }
        }
        fail("compact-u16 continues past the third byte");
    };
    auto short_vec = [&] { return r.take(compact_u16()); };
    tx.signatures = read_signatures(discriminator);
    auto prefix = r.u8();
    if (prefix & 0x80) {
        auto version = prefix & 0x7F;
        require(version != 127, "off-chain messages are not accepted");
        require(version == 0, "unsupported transaction version");
        tx.version = 0;
        tx.num_required = r.u8();
    } else {
        tx.num_required = prefix;
    }
    tx.num_readonly_signed = r.u8();
    tx.num_readonly_unsigned = r.u8();
    tx.keys = read_keys(compact_u16());
    tx.recent_blockhash = r.take(32);
    tx.instructions = read_list(compact_u16(), 3, [&] {
        CompiledInstruction ix;
        ix.program = r.u8();
        ix.accounts = short_vec();
        ix.data = short_vec();
        return ix;
    });
    if (tx.version == 0) {
        tx.lookups = read_list(compact_u16(), 34, [&] {
            AddressTableLookup l;
            l.account_key = r.take(32);
            l.writable = short_vec();
            l.readonly = short_vec();
            return l;
        });
    }
    tx.raw = r.consumed();
    return tx;
}

std::optional<Meta> decode_metadata(std::uint64_t slot, Bytes frame, Arena& arena) {
    if (frame.empty()) return std::nullopt;
    return unwrap_frame(frame, arena, [slot](Bytes b) -> Meta {
        if (slot < kBincodeCutoff) {
            try {
                return bincode_metadata(b);
            } catch (const DecodeError&) {
                return convert(parse_proto_meta(b));
            }
        }
        std::optional<ProtoMeta> pm;
        try {
            pm = parse_proto_meta(b);
        } catch (const DecodeError&) {
            return bincode_metadata(b);
        }
        return convert(std::move(*pm));
    });
}

BlockRewards decode_rewards(std::uint64_t slot, Bytes frame, Arena& arena) {
    if (frame.empty()) return {};
    return unwrap_frame(frame, arena, [slot](Bytes b) -> BlockRewards {
        if (slot < kBincodeCutoff) {
            try {
                return {bincode_rewards(b), std::nullopt};
            } catch (const DecodeError&) {
                return parse_proto_rewards(b);
            }
        }
        try {
            return parse_proto_rewards(b);
        } catch (const DecodeError&) {
            return {bincode_rewards(b), std::nullopt};
        }
    });
}

}  // namespace ob
