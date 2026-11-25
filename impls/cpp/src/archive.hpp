// Old Faithful 2-range-read protocol (SPEC §4): Range client, retries and bounded RAM-only LRUs.
#pragma once

#include "onlyblocks.hpp"

#include <list>
#include <mutex>
#include <random>
#include <semaphore>

namespace ob {

/// O(1) LRU: a recency list plus an index into it, guarded by one mutex.
template <class K, class V>
class LruCache {
public:
    explicit LruCache(std::size_t capacity) : capacity_(capacity) {}

    std::optional<V> get(const K& key) {
        std::scoped_lock lock(mu_);
        auto it = index_.find(key);
        if (it == index_.end()) return std::nullopt;
        order_.splice(order_.begin(), order_, it->second);
        return it->second->second;
    }

    void put(const K& key, V value) {
        std::scoped_lock lock(mu_);
        if (auto it = index_.find(key); it != index_.end()) {
            it->second->second = std::move(value);
            order_.splice(order_.begin(), order_, it->second);
            return;
        }
        order_.emplace_front(key, std::move(value));
        index_.emplace(key, order_.begin());
        if (order_.size() > capacity_) {
            index_.erase(order_.back().first);
            order_.pop_back();
        }
    }

private:
    std::mutex mu_;
    std::size_t capacity_;
    std::list<std::pair<K, V>> order_;
    std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator> index_;
};

struct SlotRange {
    std::uint64_t offset = 0;
    std::uint32_t length = 0;  ///< 0 = skipped slot
};

class Archive {
public:
    /// Throws std::invalid_argument for anything but an http:// or https:// base URL.
    explicit Archive(std::string_view base_url);

    /// Both range reads (or a cache hit, then the CAR read). Throws RpcError or DecodeError.
    Bytes slot_slice(std::uint64_t slot, Arena& arena);

    std::optional<std::string> cached_hash(std::uint64_t slot) { return hashes_.get(slot); }
    void cache_hash(std::uint64_t slot, const std::string& hash) { hashes_.put(slot, hash); }

private:
    struct Attempt;
    struct Sink;
    Bytes read_range(std::uint64_t slot, std::string_view suffix, std::uint64_t start, std::uint64_t length,
                     std::uint64_t cap, Arena& arena);
    void http_attempt(const std::string& path, std::uint64_t start, std::uint64_t end, Sink& sink, Attempt& at) const;
    void https_attempt(const std::string& path, std::uint64_t start, std::uint64_t end, Sink& sink, Attempt& at) const;
    double jitter();

    bool https_ = false;
    std::string authority_, host_, port_, prefix_;
    LruCache<std::uint64_t, SlotRange> ranges_{100'000};
    LruCache<std::uint64_t, std::string> hashes_{100'000};
    std::counting_semaphore<32> inflight_{32};
    std::mutex rng_mu_;
    std::mt19937_64 rng_{std::random_device{}()};
};

}  // namespace ob
