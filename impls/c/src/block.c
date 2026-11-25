/* The getBlock pipeline (SPEC §4.5) and its JSON serialization (WIRE_FORMATS.md §13–14). */
#include "model.h"

#include <stdio.h>

static const char ZERO_HASH[] = "11111111111111111111111111111111";
static const char UPGRADEABLE_LOADER[] = "BPFLoaderUpgradeab1e11111111111111111111111";
static const char *const RESERVED[] = {
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
    "Sysvar1111111111111111111111111111111111111",
};

typedef struct {
    tx_t tx;
    meta_t *meta;  /* NULL with missing == true: MissingMetadata */
    bool missing;
} txm_t;

typedef struct {
    char s[45];
} key58_t;

/* ------------------------------------------------------------------ block loading */

static void entry_hash(ctx_t *c, const cbor_t *entry, const uint8_t **hash) {
    const cbor_t *h = cbor_at(entry, 2);
    if (!h || h->t != CB_BYTES || h->b.n != 32) DIE(c, "invalid Entry hash");
    *hash = h->b.p;
}

/* Base58 hash of the last Entry, or 32 zero bytes when there are none. */
static void last_entry_hash(ctx_t *c, const car_t *car, const block_node_t *blk, char out[45]) {
    if (blk->entries.n == 0) {
        memcpy(out, ZERO_HASH, sizeof ZERO_HASH);
        return;
    }
    const uint8_t *h;
    entry_hash(c, car_node(c, car, blk->entries.v[blk->entries.n - 1], 1), &h);
    b58_32(out, h);
}

static void load_block(ctx_t *c, archive_t *a, uint64_t slot, car_t *car, block_node_t *blk) {
    bytes_t slice = archive_slot_slice(c, a, slot);
    car_index(c, slice, car);
    if (!car->has_block) DIE(c, "CAR slice is missing its Block node");
    parse_block_node(c, cbor_decode(c, car->block), blk);
}

static void previous_hash(ctx_t *c, archive_t *a, uint64_t slot, uint64_t parent, char out[45]) {
    if (slot == 0) {
        memcpy(out, ZERO_HASH, sizeof ZERO_HASH);
        return;
    }
    if (archive_hash_get(a, parent, out)) return;
    car_t car;
    block_node_t blk;
    load_block(c, a, parent, &car, &blk); /* the parent's Block.slot is not checked */
    last_entry_hash(c, &car, &blk, out);
    archive_hash_put(a, parent, out);
}

/* ------------------------------------------------------------------ account keys */

typedef struct {
    const tx_t *tx;
    const meta_t *meta; /* loaded addresses apply to v0 with metadata */
    size_t total, nw;
    key58_t *names;
} keys_t;

static const uint8_t *key_bytes(const keys_t *k, size_t i) {
    if (i < k->tx->nkeys) return k->tx->keys + 32 * i;
    i -= k->tx->nkeys;
    if (i < k->nw) return k->meta->loaded_w.v[i];
    return k->meta->loaded_r.v[i - k->nw];
}

static void keys_init(ctx_t *c, keys_t *k, const txm_t *t) {
    k->tx = &t->tx;
    k->meta = t->meta;
    k->nw = 0;
    k->total = t->tx.nkeys;
    if (t->tx.version == 0 && t->meta) {
        k->nw = t->meta->loaded_w.n;
        k->total += t->meta->loaded_w.n + t->meta->loaded_r.n;
    }
    k->names = amalloc(c, (k->total ? k->total : 1) * sizeof(key58_t));
    for (size_t i = 0; i < k->total; i++) b58_32(k->names[i].s, key_bytes(k, i));
}

static bool is_reserved(const char *s) {
    for (size_t i = 0; i < sizeof RESERVED / sizeof *RESERVED; i++)
        if (strcmp(s, RESERVED[i]) == 0) return true;
    return false;
}

static void emit_account_keys(ctx_t *c, jw_t *w, const keys_t *k) {
    (void)c;
    const tx_t *tx = k->tx;
    size_t s = tx->nkeys;
    bool upgradeable = false;
    for (size_t i = 0; i < k->total; i++)
        if (strcmp(k->names[i].s, UPGRADEABLE_LOADER) == 0) upgradeable = true;
    jw_arr(w);
    for (size_t i = 0; i < k->total; i++) {
        bool writable;
        if (i >= s) writable = (i - s) < k->nw;
        else if (i >= tx->nrs) writable = (i - tx->nrs) < (s > (size_t)tx->nrs + tx->nrou ? s - tx->nrs - tx->nrou : 0);
        else writable = i < (size_t)(tx->nrs > tx->nros ? tx->nrs - tx->nros : 0);
        bool demoted = false;
        if (i <= 255 && !upgradeable)
            for (size_t j = 0; j < tx->nix; j++)
                if (tx->ix[j].program == i) demoted = true;
        writable = writable && !demoted && !is_reserved(k->names[i].s);
        jw_obj(w);
        jw_key(w, "pubkey");
        jw_cstr(w, k->names[i].s);
        jw_key(w, "writable");
        jw_bool(w, writable);
        jw_key(w, "signer");
        jw_bool(w, i < tx->nrs);
        jw_key(w, "source");
        jw_cstr(w, i >= s ? "lookupTable" : "transaction");
        jw_end_obj(w);
    }
    jw_end_arr(w);
}

static const char *key_name(ctx_t *c, const keys_t *k, size_t i) {
    if (i >= k->total) DIE(c, "instruction account index out of range");
    return k->names[i].s;
}

/* ------------------------------------------------------------------ instructions */

static void emit_bytes_array(jw_t *w, bytes_t b) {
    jw_arr(w);
    for (size_t i = 0; i < b.n; i++) jw_u64(w, b.p[i]);
    jw_end_arr(w);
}

static void emit_instruction(ctx_t *c, jw_t *w, const keys_t *parsed, uint8_t program, bytes_t accounts, bytes_t data,
                             bool has_stack, uint32_t stack) {
    jw_obj(w);
    if (parsed) {
        jw_key(w, "programId");
        jw_cstr(w, key_name(c, parsed, program));
        jw_key(w, "accounts");
        jw_arr(w);
        for (size_t i = 0; i < accounts.n; i++) jw_cstr(w, key_name(c, parsed, accounts.p[i]));
        jw_end_arr(w);
    } else {
        jw_key(w, "programIdIndex");
        jw_u64(w, program);
        jw_key(w, "accounts");
        emit_bytes_array(w, accounts);
    }
    jw_key(w, "data");
    jw_b58(c, w, data.p, data.n);
    jw_key(w, "stackHeight");
    if (has_stack) jw_u64(w, stack);
    else jw_null(w);
    jw_end_obj(w);
}

/* ------------------------------------------------------------------ metadata */

static void emit_reward(ctx_t *c, jw_t *w, const reward_t *r) {
    static const char *const TYPES[5] = {NULL, "Fee", "Rent", "Staking", "Voting"};
    (void)c;
    jw_obj(w);
    jw_key(w, "pubkey");
    jw_str(w, r->pubkey.p, r->pubkey.n);
    jw_key(w, "lamports");
    jw_i64(w, r->lamports);
    jw_key(w, "postBalance");
    jw_u64(w, r->post_balance);
    jw_key(w, "rewardType");
    if (r->reward_type) jw_cstr(w, TYPES[r->reward_type]);
    else jw_null(w);
    jw_key(w, "commission");
    if (r->has_commission) jw_u64(w, r->commission);
    else jw_null(w);
    jw_end_obj(w);
}

static void emit_rewards(ctx_t *c, jw_t *w, const rewards_vec_t *v) {
    jw_arr(w);
    for (size_t i = 0; i < v->n; i++) emit_reward(c, w, &v->v[i]);
    jw_end_arr(w);
}

static void emit_tokens(jw_t *w, bool has, const tokens_vec_t *v) {
    if (!has) { jw_null(w); return; }
    jw_arr(w);
    for (size_t i = 0; i < v->n; i++) {
        const token_t *t = &v->v[i];
        jw_obj(w);
        jw_key(w, "accountIndex");
        jw_u64(w, t->account_index);
        jw_key(w, "mint");
        jw_str(w, t->mint.p, t->mint.n);
        jw_key(w, "uiTokenAmount");
        jw_obj(w);
        jw_key(w, "uiAmount");
        if (t->has_ui) jw_f64(w, t->ui);
        else jw_null(w);
        jw_key(w, "decimals");
        jw_u64(w, t->decimals);
        jw_key(w, "amount");
        jw_str(w, t->amount.p, t->amount.n);
        jw_key(w, "uiAmountString");
        jw_str(w, t->ui_string.p, t->ui_string.n);
        jw_end_obj(w);
        if (t->owner.n) { jw_key(w, "owner"); jw_str(w, t->owner.p, t->owner.n); }
        if (t->program_id.n) { jw_key(w, "programId"); jw_str(w, t->program_id.p, t->program_id.n); }
        jw_end_obj(w);
    }
    jw_end_arr(w);
}

static void emit_u64s(jw_t *w, const u64_vec_t *v) {
    jw_arr(w);
    for (size_t i = 0; i < v->n; i++) jw_u64(w, v->v[i]);
    jw_end_arr(w);
}

static void emit_meta(ctx_t *c, jw_t *w, const block_opts_t *o, const meta_t *m, const keys_t *parsed) {
    bool accounts = o->details == TD_ACCOUNTS;
    jw_obj(w);
    jw_key(w, "err");
    if (m->err_json) jw_rawval(w, m->err_json, strlen(m->err_json));
    else jw_null(w);
    jw_key(w, "status");
    jw_obj(w);
    if (m->err_json) {
        jw_key(w, "Err");
        jw_rawval(w, m->err_json, strlen(m->err_json));
    } else {
        jw_key(w, "Ok");
        jw_null(w);
    }
    jw_end_obj(w);
    jw_key(w, "fee");
    jw_u64(w, m->fee);
    jw_key(w, "preBalances");
    emit_u64s(w, &m->pre);
    jw_key(w, "postBalances");
    emit_u64s(w, &m->post);
    jw_key(w, "preTokenBalances");
    emit_tokens(w, m->has_pre_tokens, &m->pre_tokens);
    jw_key(w, "postTokenBalances");
    emit_tokens(w, m->has_post_tokens, &m->post_tokens);
    if (o->rewards) {
        jw_key(w, "rewards");
        if (m->has_rewards) emit_rewards(c, w, &m->rewards);
        else jw_null(w);
    } else if (!accounts) {
        jw_key(w, "rewards");
        jw_null(w);
    }
    if (!accounts) {
        jw_key(w, "innerInstructions");
        if (m->has_inner) {
            jw_arr(w);
            for (size_t i = 0; i < m->inner.n; i++) {
                const inner_t *in = &m->inner.v[i];
                jw_obj(w);
                jw_key(w, "index");
                jw_u64(w, in->index);
                jw_key(w, "instructions");
                jw_arr(w);
                for (size_t j = 0; j < in->ix.n; j++) {
                    const iix_t *ix = &in->ix.v[j];
                    emit_instruction(c, w, parsed, ix->program, ix->accounts, ix->data, ix->has_stack, ix->stack);
                }
                jw_end_arr(w);
                jw_end_obj(w);
            }
            jw_end_arr(w);
        } else {
            jw_null(w);
        }
        jw_key(w, "logMessages");
        if (m->has_logs) {
            jw_arr(w);
            for (size_t i = 0; i < m->logs.n; i++) jw_str(w, m->logs.v[i].p, m->logs.v[i].n);
            jw_end_arr(w);
        } else {
            jw_null(w);
        }
        if (o->encoding != ENC_PARSED) {
            jw_key(w, "loadedAddresses");
            jw_obj(w);
            jw_key(w, "writable");
            jw_arr(w);
            for (size_t i = 0; i < m->loaded_w.n; i++) jw_b58(c, w, m->loaded_w.v[i], 32);
            jw_end_arr(w);
            jw_key(w, "readonly");
            jw_arr(w);
            for (size_t i = 0; i < m->loaded_r.n; i++) jw_b58(c, w, m->loaded_r.v[i], 32);
            jw_end_arr(w);
            jw_end_obj(w);
        }
        if (m->has_return) {
            jw_key(w, "returnData");
            jw_obj(w);
            jw_key(w, "programId");
            jw_b58(c, w, m->return_program, 32);
            jw_key(w, "data");
            jw_arr(w);
            jw_b64(w, m->return_data.p, m->return_data.n);
            jw_cstr(w, "base64");
            jw_end_arr(w);
            jw_end_obj(w);
        }
        if (m->has_cu) { jw_key(w, "computeUnitsConsumed"); jw_u64(w, m->cu); }
        if (m->has_cost) { jw_key(w, "costUnits"); jw_u64(w, m->cost); }
    }
    jw_end_obj(w);
}

/* ------------------------------------------------------------------ transactions */

static void emit_signatures(ctx_t *c, jw_t *w, const tx_t *tx) {
    jw_arr(w);
    for (size_t i = 0; i < tx->nsigs; i++) jw_b58(c, w, tx->sigs + 64 * i, 64);
    jw_end_arr(w);
}

static void emit_config_value(jw_t *w, const char *name, bool present, uint64_t value) {
    jw_key(w, name);
    if (present) jw_u64(w, value);
    else jw_null(w);
}

static void emit_transaction_config(jw_t *w, const tx_t *tx) {
    jw_key(w, "transactionConfig");
    jw_obj(w);
    emit_config_value(w, "priorityFee", tx->config_mask & 3, tx->priority_fee);
    emit_config_value(w, "computeUnitLimit", tx->config_mask & 4, tx->compute_unit_limit);
    emit_config_value(w, "loadedAccountsDataSizeLimit", tx->config_mask & 8, tx->loaded_accounts_data_size_limit);
    emit_config_value(w, "heapSize", tx->config_mask & 16, tx->heap_size);
    jw_end_obj(w);
}

static void emit_tx(ctx_t *c, jw_t *w, const block_opts_t *o, const txm_t *t) {
    const tx_t *tx = &t->tx;
    if (!t->missing && tx->version >= 0 && o->max_version < tx->version)
        fail(c, E_VERSION,
             "Transaction version (%d) is not supported by the requesting client. Please try the request again with the "
             "following configuration parameter: \"maxSupportedTransactionVersion\": %d", tx->version, tx->version);
    bool parsed = o->encoding == ENC_PARSED, accounts = o->details == TD_ACCOUNTS;
    keys_t keys;
    if (parsed || accounts) keys_init(c, &keys, t);
    jw_obj(w);
    jw_key(w, "transaction");
    if (o->encoding == ENC_BASE64 || o->encoding == ENC_BASE58) {
        jw_arr(w);
        if (o->encoding == ENC_BASE64) jw_b64(w, tx->raw.p, tx->raw.n);
        else jw_b58(c, w, tx->raw.p, tx->raw.n);
        jw_cstr(w, o->encoding == ENC_BASE64 ? "base64" : "base58");
        jw_end_arr(w);
    } else if (accounts) {
        jw_obj(w);
        jw_key(w, "signatures");
        emit_signatures(c, w, tx);
        jw_key(w, "accountKeys");
        emit_account_keys(c, w, &keys);
        jw_end_obj(w);
    } else {
        jw_obj(w);
        jw_key(w, "signatures");
        emit_signatures(c, w, tx);
        jw_key(w, "message");
        jw_obj(w);
        if (!parsed) {
            jw_key(w, "header");
            jw_obj(w);
            jw_key(w, "numRequiredSignatures");
            jw_u64(w, tx->nrs);
            jw_key(w, "numReadonlySignedAccounts");
            jw_u64(w, tx->nros);
            jw_key(w, "numReadonlyUnsignedAccounts");
            jw_u64(w, tx->nrou);
            jw_end_obj(w);
        }
        jw_key(w, "accountKeys");
        if (parsed) {
            emit_account_keys(c, w, &keys);
        } else {
            jw_arr(w);
            for (size_t i = 0; i < tx->nkeys; i++) jw_b58(c, w, tx->keys + 32 * i, 32);
            jw_end_arr(w);
        }
        jw_key(w, "recentBlockhash");
        jw_b58(c, w, tx->blockhash, 32);
        jw_key(w, "instructions");
        jw_arr(w);
        for (size_t i = 0; i < tx->nix; i++)
            emit_instruction(c, w, parsed ? &keys : NULL, tx->ix[i].program, tx->ix[i].accounts, tx->ix[i].data, true, 1);
        jw_end_arr(w);
        if (tx->version == 0) {
            jw_key(w, "addressTableLookups");
            jw_arr(w);
            for (size_t i = 0; i < tx->nlookups; i++) {
                jw_obj(w);
                jw_key(w, "accountKey");
                jw_b58(c, w, tx->lookups[i].key, 32);
                jw_key(w, "writableIndexes");
                emit_bytes_array(w, tx->lookups[i].writable);
                jw_key(w, "readonlyIndexes");
                emit_bytes_array(w, tx->lookups[i].readonly);
                jw_end_obj(w);
            }
            jw_end_arr(w);
        } else if (tx->version == 1) {
            emit_transaction_config(w, tx);
        }
        jw_end_obj(w);
        jw_end_obj(w);
    }
    jw_key(w, "meta");
    if (t->missing) jw_null(w);
    else emit_meta(c, w, o, t->meta, parsed ? &keys : NULL);
    if (!t->missing && o->max_version >= 0) {
        jw_key(w, "version");
        if (tx->version >= 0) jw_u64(w, (uint64_t)tx->version);
        else jw_cstr(w, "legacy");
    }
    jw_end_obj(w);
}

/* ------------------------------------------------------------------ pipeline */

void get_block(ctx_t *c, archive_t *a, const block_opts_t *o, jw_t *w) {
    car_t car;
    block_node_t blk;
    load_block(c, a, o->slot, &car, &blk);
    if (blk.slot != o->slot) DIE(c, "Block slot %llu differs from the requested slot", (unsigned long long)blk.slot);
    char hash[45], prev[45];
    last_entry_hash(c, &car, &blk, hash);
    archive_hash_put(a, o->slot, hash);
    previous_hash(c, a, o->slot, blk.parent_slot, prev);

    VEC(txm_t) txs = {0};
    VEC(const uint8_t *) sigs = {0};
    if (o->details != TD_NONE) {
        for (size_t e = 0; e < blk.entries.n; e++) {
            const cbor_t *entry = car_node(c, &car, blk.entries.v[e], 1);
            const uint8_t *eh;
            entry_hash(c, entry, &eh);
            bytes_vec_t links = {0};
            const cbor_t *list = cbor_at(entry, 3);
            if (list && list->t == CB_ARR)
                for (size_t i = 0; i < list->n; i++) VPUSH(c, links, parse_link(c, &list->a[i]).key);
            for (size_t i = 0; i < links.n; i++) {
                const cbor_t *node = car_node(c, &car, links.v[i], 0);
                dataframe_t df;
                const cbor_t *data = cbor_at(node, 1);
                if (!data) DIE(c, "Transaction node has no data");
                parse_dataframe(c, data, &df);
                /* The node's metadata DataFrame is parsed with the node (errors propagate, §5);
                   its payload is reassembled and decoded only when metadata is wanted (§7). */
                const cbor_t *md = cbor_at(node, 2);
                dataframe_t mdf;
                bool has_md = md && md->t == CB_ARR;
                if (has_md) parse_dataframe(c, md, &mdf);
                VRESERVE(c, txs);
                txm_t *t = &txs.v[txs.n];
                memset(t, 0, sizeof *t);
                parse_transaction(c, reassemble(c, &car, &df), &t->tx);
                if (o->details == TD_SIGNATURES) {
                    if (t->tx.nsigs == 0) DIE(c, "transaction has no signature");
                    VPUSH(c, sigs, t->tx.sigs);
                    continue;
                }
                meta_t *m = has_md ? decode_metadata(c, o->slot, reassemble(c, &car, &mdf)) : NULL;
                if (!m && t->tx.version >= 0) m = acalloc(c, 1, sizeof *m); /* default_meta */
                t->meta = m;
                t->missing = m == NULL;
                txs.n++;
            }
        }
    }

    block_rewards_t rewards = {0};
    if (o->rewards && blk.has_rewards) {
        bytes_t node;
        if (car_get(&car, blk.rewards, &node)) {
            const cbor_t *rn = car_node(c, &car, blk.rewards, 5);
            bytes_t payload = {(const uint8_t *)"", 0};
            const cbor_t *data = cbor_at(rn, 2);
            if (data) {
                dataframe_t df;
                parse_dataframe(c, data, &df);
                payload = reassemble(c, &car, &df);
            }
            decode_rewards(c, o->slot, payload, &rewards);
        }
    }

    jw_obj(w);
    jw_key(w, "previousBlockhash");
    jw_cstr(w, prev);
    jw_key(w, "blockhash");
    jw_cstr(w, hash);
    jw_key(w, "parentSlot");
    jw_u64(w, blk.parent_slot);
    if (o->details == TD_SIGNATURES) {
        jw_key(w, "signatures");
        jw_arr(w);
        for (size_t i = 0; i < sigs.n; i++) jw_b58(c, w, sigs.v[i], 64);
        jw_end_arr(w);
    } else if (o->details != TD_NONE) {
        jw_key(w, "transactions");
        jw_arr(w);
        for (size_t i = 0; i < txs.n; i++) emit_tx(c, w, o, &txs.v[i]);
        jw_end_arr(w);
    }
    if (o->rewards) {
        jw_key(w, "rewards");
        emit_rewards(c, w, &rewards.list);
        if (rewards.has_partitions) {
            jw_key(w, "numRewardPartitions");
            jw_u64(w, rewards.partitions);
        }
    }
    jw_key(w, "blockTime");
    if (blk.has_blocktime) jw_i64(w, blk.blocktime);
    else jw_null(w);
    jw_key(w, "blockHeight");
    if (blk.has_height) jw_u64(w, blk.height);
    else jw_null(w);
    jw_end_obj(w);
}
