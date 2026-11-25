#include "block.hpp"

#include "ipld.hpp"
#include "solana.hpp"

#include <algorithm>

namespace ob {
namespace {

constexpr std::string_view kZeroHash = "11111111111111111111111111111111";
constexpr std::string_view kUpgradeableLoader = "BPFLoaderUpgradeab1e11111111111111111111111";
constexpr std::array<std::string_view, 31> kReserved{
    "AddressLookupTab1e1111111111111111111111111", "BPFLoader2111111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111", "BPFLoaderUpgradeab1e11111111111111111111111",
    "ComputeBudget111111111111111111111111111111", "Config1111111111111111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111", "Feature111111111111111111111111111111111111",
    "LoaderV411111111111111111111111111111111111", "KeccakSecp256k11111111111111111111111111111",
    "Secp256r1SigVerify1111111111111111111111111", "StakeConfig11111111111111111111111111111111",
    "Stake11111111111111111111111111111111111111", "11111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111", "ZkE1Gama1Proof11111111111111111111111111111",
    "ZkTokenProof1111111111111111111111111111111", "SysvarC1ock11111111111111111111111111111111",
    "SysvarEpochRewards1111111111111111111111111", "SysvarEpochSchedu1e111111111111111111111111",
    "SysvarFees111111111111111111111111111111111", "Sysvar1nstructions1111111111111111111111111",
    "SysvarLastRestartS1ot1111111111111111111111", "SysvarRecentB1ockHashes11111111111111111111",
    "SysvarRent111111111111111111111111111111111", "SysvarRewards111111111111111111111111111111",
    "SysvarS1otHashes111111111111111111111111111", "SysvarS1otHistory11111111111111111111111111",
    "SysvarStakeHistory1111111111111111111111111", "NativeLoader1111111111111111111111111111111",
    "Sysvar1111111111111111111111111111111111111"};

/// A decoded transaction: `meta` is empty exactly for MissingMetadata (legacy, empty frame).
struct TxWithMeta {
    Transaction tx;
    std::optional<Meta> meta;
};

Bytes entry_hash(const Cbor& entry) {
    const auto* h = entry.at(2);
    require(h && h->is_bytes() && h->bytes.size() == 32, "invalid Entry hash");
    return h->bytes;
}

std::string last_entry_hash(const CarIndex& car, const BlockNode& block) {
    if (block.entries.empty()) return std::string(kZeroHash);
    return base58(entry_hash(car.node(block.entries.back(), 1)));
}

struct LoadedBlock {
    CarIndex car;
    BlockNode node;
};

LoadedBlock load_block(Archive& archive, std::uint64_t slot, Arena& arena) {
    CarIndex car(archive.slot_slice(slot, arena), arena);
    require(car.block().has_value(), "CAR slice is missing its Block node");
    auto node = BlockNode::parse(decode_cbor(*car.block(), arena));
    return {std::move(car), std::move(node)};
}

std::string previous_hash(Archive& archive, std::uint64_t slot, std::uint64_t parent, Arena& arena) {
    if (slot == 0) return std::string(kZeroHash);
    if (auto cached = archive.cached_hash(parent)) return *cached;
    auto loaded = load_block(archive, parent, arena);  // the parent's Block.slot is not checked
    auto hash = last_entry_hash(loaded.car, loaded.node);
    archive.cache_hash(parent, hash);
    return hash;
}

/// The combined key list: static keys, then (v0 with metadata) loaded writable and readonly.
struct AccountKeys {
    std::vector<std::string> names;
    std::size_t statics = 0, loaded_writable = 0;

    AccountKeys(const Transaction& tx, const Meta* meta) : statics(tx.keys.size()) {
        for (auto k : tx.keys) names.push_back(base58(k));
        if (tx.v0 && meta) {
            loaded_writable = meta->loaded_writable.size();
            for (auto k : meta->loaded_writable) names.push_back(base58(k));
            for (auto k : meta->loaded_readonly) names.push_back(base58(k));
        }
    }

    [[nodiscard]] const std::string& at(std::size_t i) const {
        require(i < names.size(), "instruction account index out of range");
        return names[i];
    }

    /// WIRE_FORMATS.md §14: header-derived writability, minus reserved keys and demoted program ids.
    void write(JsonWriter& w, const Transaction& tx) const {
        bool upgradeable = std::ranges::find(names, kUpgradeableLoader) != names.end();
        std::size_t nrs = tx.num_required, nros = tx.num_readonly_signed, nrou = tx.num_readonly_unsigned;
        w.array([&] {
            for (std::size_t i = 0; i < names.size(); ++i) {
                bool writable = i >= statics ? i - statics < loaded_writable
                                : i >= nrs   ? i - nrs < (statics > nrs + nrou ? statics - nrs - nrou : 0)
                                             : i < (nrs > nros ? nrs - nros : 0);
                bool demoted = !upgradeable && std::ranges::any_of(tx.instructions, [&](const auto& ix) { return ix.program == i; });
                writable = writable && !demoted && std::ranges::find(kReserved, names[i]) == kReserved.end();
                w.object([&] {
                    w.field("pubkey", names[i]);
                    w.field("writable", writable);
                    w.field("signer", i < nrs);
                    w.field("source", i >= statics ? "lookupTable" : "transaction");
                });
            }
        });
    }
};

class Serializer {
public:
    Serializer(JsonWriter& w, const BlockOptions& o) : w_(w), o_(o) {}

    void transaction(const TxWithMeta& t) {
        const auto& tx = t.tx;
        if (t.meta && tx.v0 && !o_.max_version)
            throw RpcError(code::version,
                           "Transaction version (0) is not supported by the requesting client. Please try the request "
                           "again with the following configuration parameter: \"maxSupportedTransactionVersion\": 0");
        bool parsed = o_.encoding == Encoding::JsonParsed, accounts = o_.details == Details::Accounts;
        std::optional<AccountKeys> keys;
        if (parsed || accounts) keys.emplace(tx, t.meta ? &*t.meta : nullptr);
        const AccountKeys* resolve = parsed ? &*keys : nullptr;
        w_.object([&] {
            w_.key("transaction");
            if (o_.encoding == Encoding::Base64 || o_.encoding == Encoding::Base58) {
                w_.array([&] {
                    if (o_.encoding == Encoding::Base64) w_.value(Base64{tx.raw});
                    else w_.value(Base58{tx.raw});
                    w_.value(o_.encoding == Encoding::Base64 ? "base64" : "base58");
                });
            } else if (accounts) {
                w_.object([&] {
                    signatures(tx);
                    w_.key("accountKeys");
                    keys->write(w_, tx);
                });
            } else {
                w_.object([&] {
                    signatures(tx);
                    w_.key("message");
                    message(tx, resolve);
                });
            }
            w_.key("meta");
            if (t.meta) meta(*t.meta, resolve);
            else w_.value(nullptr);
            if (t.meta && o_.max_version) {
                if (tx.v0) w_.field("version", 0);
                else w_.field("version", "legacy");
            }
        });
    }

    void rewards(const std::vector<Reward>& list) {
        w_.array_of(list, [&](const Reward& r) {
            w_.object([&] {
                w_.field("pubkey", r.pubkey);
                w_.field("lamports", r.lamports);
                w_.field("postBalance", r.post_balance);
                w_.field("rewardType", r.reward_type);
                w_.field("commission", r.commission);
            });
        });
    }

private:
    void signatures(const Transaction& tx) {
        w_.key("signatures");
        w_.array_of(tx.signatures, [&](Bytes sig) { w_.value(Base58{sig}); });
    }

    void index_array(Bytes indexes) {
        w_.array_of(indexes, [&](std::uint8_t i) { w_.value(i); });
    }

    void instruction(const AccountKeys* keys, std::uint8_t program, Bytes accounts, Bytes data,
                     std::optional<std::uint32_t> stack_height) {
        w_.object([&] {
            if (keys) {
                w_.field("programId", keys->at(program));
                w_.key("accounts");
                w_.array_of(accounts, [&](std::uint8_t i) { w_.value(keys->at(i)); });
            } else {
                w_.field("programIdIndex", program);
                w_.key("accounts");
                index_array(accounts);
            }
            w_.field("data", Base58{data});
            w_.field("stackHeight", stack_height);
        });
    }

    void message(const Transaction& tx, const AccountKeys* keys) {
        w_.object([&] {
            if (!keys) {
                w_.key("header");
                w_.object([&] {
                    w_.field("numRequiredSignatures", tx.num_required);
                    w_.field("numReadonlySignedAccounts", tx.num_readonly_signed);
                    w_.field("numReadonlyUnsignedAccounts", tx.num_readonly_unsigned);
                });
            }
            w_.key("accountKeys");
            if (keys) keys->write(w_, tx);
            else w_.array_of(tx.keys, [&](Bytes k) { w_.value(Base58{k}); });
            w_.field("recentBlockhash", Base58{tx.recent_blockhash});
            w_.key("instructions");
            w_.array_of(tx.instructions, [&](const CompiledInstruction& ix) {
                instruction(keys, ix.program, ix.accounts, ix.data, 1u);  // TRANSACTION_LEVEL_STACK_HEIGHT
            });
            if (tx.v0) {
                w_.key("addressTableLookups");
                w_.array_of(tx.lookups, [&](const AddressTableLookup& l) {
                    w_.object([&] {
                        w_.field("accountKey", Base58{l.account_key});
                        w_.key("writableIndexes");
                        index_array(l.writable);
                        w_.key("readonlyIndexes");
                        index_array(l.readonly);
                    });
                });
            }
        });
    }

    void token_balances(const std::optional<std::vector<TokenBalance>>& list) {
        if (!list) return w_.value(nullptr);
        w_.array_of(*list, [&](const TokenBalance& t) {
            w_.object([&] {
                w_.field("accountIndex", t.account_index);
                w_.field("mint", t.mint);
                w_.key("uiTokenAmount");
                w_.object([&] {
                    w_.field("uiAmount", t.ui_amount);
                    w_.field("decimals", t.decimals);
                    w_.field("amount", t.amount);
                    w_.field("uiAmountString", t.ui_amount_string);
                });
                if (!t.owner.empty()) w_.field("owner", t.owner);
                if (!t.program_id.empty()) w_.field("programId", t.program_id);
            });
        });
    }

    void meta(const Meta& m, const AccountKeys* keys) {
        bool accounts = o_.details == Details::Accounts;
        auto err = m.err ? std::optional<std::string>(m.err->json()) : std::nullopt;
        w_.object([&] {
            w_.key("err");
            if (err) w_.value(RawJson{*err});
            else w_.value(nullptr);
            w_.key("status");
            w_.object([&] {
                if (err) w_.field("Err", RawJson{*err});
                else w_.field("Ok", nullptr);
            });
            w_.field("fee", m.fee);
            w_.key("preBalances");
            w_.array_of(m.pre_balances, [&](std::uint64_t v) { w_.value(v); });
            w_.key("postBalances");
            w_.array_of(m.post_balances, [&](std::uint64_t v) { w_.value(v); });
            w_.key("preTokenBalances");
            token_balances(m.pre_token_balances);
            w_.key("postTokenBalances");
            token_balances(m.post_token_balances);
            if (o_.rewards) {
                w_.key("rewards");
                if (m.rewards) rewards(*m.rewards);
                else w_.value(nullptr);
            } else if (!accounts) {
                w_.field("rewards", nullptr);
            }
            if (accounts) return;
            w_.key("innerInstructions");
            if (!m.inner_instructions) {
                w_.value(nullptr);
            } else {
                w_.array_of(*m.inner_instructions, [&](const InnerInstructions& group) {
                    w_.object([&] {
                        w_.field("index", group.index);
                        w_.key("instructions");
                        w_.array_of(group.instructions, [&](const InnerInstruction& ix) {
                            instruction(keys, ix.program, ix.accounts, ix.data, ix.stack_height);
                        });
                    });
                });
            }
            w_.key("logMessages");
            if (m.log_messages) w_.array_of(*m.log_messages, [&](std::string_view s) { w_.value(s); });
            else w_.value(nullptr);
            if (o_.encoding != Encoding::JsonParsed) {
                w_.key("loadedAddresses");
                w_.object([&] {
                    w_.key("writable");
                    w_.array_of(m.loaded_writable, [&](Bytes k) { w_.value(Base58{k}); });
                    w_.key("readonly");
                    w_.array_of(m.loaded_readonly, [&](Bytes k) { w_.value(Base58{k}); });
                });
            }
            if (m.return_data) {
                w_.key("returnData");
                w_.object([&] {
                    w_.field("programId", Base58{m.return_data->program_id});
                    w_.key("data");
                    w_.array([&] {
                        w_.value(Base64{m.return_data->data});
                        w_.value("base64");
                    });
                });
            }
            if (m.compute_units_consumed) w_.field("computeUnitsConsumed", *m.compute_units_consumed);
            if (m.cost_units) w_.field("costUnits", *m.cost_units);
        });
    }

    JsonWriter& w_;
    const BlockOptions& o_;
};

}  // namespace

void get_block(Archive& archive, const BlockOptions& o, JsonWriter& w) {
    Arena arena;
    auto [car, block] = load_block(archive, o.slot, arena);
    require(block.slot == o.slot, std::format("Block slot {} differs from the requested slot", block.slot));
    auto hash = last_entry_hash(car, block);
    archive.cache_hash(o.slot, hash);
    auto previous = previous_hash(archive, o.slot, block.parent_slot, arena);

    std::vector<TxWithMeta> transactions;
    std::vector<Bytes> first_signatures;
    if (o.details != Details::None) {
        for (auto entry_cid : block.entries) {
            auto entry = car.node(entry_cid, 1);
            entry_hash(entry);
            std::vector<std::string_view> tx_links;
            if (const auto* list = entry.at(3); list && list->is_array())
                for (const auto& link : list->items) tx_links.push_back(parse_link(&link).key);
            for (auto tx_cid : tx_links) {
                auto node = car.node(tx_cid, 0);
                const auto* data = node.at(1);
                require(data != nullptr, "Transaction node has no data");
                auto tx_frame = DataFrame::parse(*data);
                // The metadata DataFrame is parsed with its node (errors propagate, §5); its payload
                // is reassembled and decoded only when metadata is wanted (§7).
                std::optional<DataFrame> meta_frame;
                if (const auto* md = node.at(2); md && md->is_array()) meta_frame = DataFrame::parse(*md);
                auto tx = Transaction::parse(tx_frame.reassemble(car));
                if (o.details == Details::Signatures) {
                    require(!tx.signatures.empty(), "transaction has no signature");
                    first_signatures.push_back(tx.signatures.front());
                    continue;
                }
                std::optional<Meta> meta;
                if (meta_frame) meta = decode_metadata(o.slot, meta_frame->reassemble(car), arena);
                if (!meta && tx.v0) meta.emplace();  // default_meta for a v0 transaction
                transactions.push_back({std::move(tx), std::move(meta)});
            }
        }
    }

    BlockRewards rewards;
    if (o.rewards && block.rewards && car.find(*block.rewards)) {
        auto node = car.node(*block.rewards, 5);
        Bytes payload;
        if (const auto* data = node.at(2)) payload = DataFrame::parse(*data).reassemble(car);
        rewards = decode_rewards(o.slot, payload, arena);
    }

    Serializer s(w, o);
    w.object([&] {
        w.field("previousBlockhash", previous);
        w.field("blockhash", hash);
        w.field("parentSlot", block.parent_slot);
        if (o.details == Details::Signatures) {
            w.key("signatures");
            w.array_of(first_signatures, [&](Bytes sig) { w.value(Base58{sig}); });
        } else if (o.details != Details::None) {
            w.key("transactions");
            w.array_of(transactions, [&](const TxWithMeta& t) { s.transaction(t); });
        }
        if (o.rewards) {
            w.key("rewards");
            s.rewards(rewards.rewards);
            if (rewards.partitions) w.field("numRewardPartitions", *rewards.partitions);
        }
        w.field("blockTime", block.block_time);
        w.field("blockHeight", block.block_height);
    });
}

}  // namespace ob
