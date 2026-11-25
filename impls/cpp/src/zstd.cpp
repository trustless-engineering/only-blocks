// RFC 8878 Zstandard decoder (docs/ZSTD_MINI_SPEC.md): whole-buffer, no dictionaries.
#include "onlyblocks.hpp"

namespace ob {
namespace {

[[noreturn]] void zerr(std::string_view what) { throw DecodeError(std::format("zstd: {}", what)); }

constexpr std::uint32_t kMagic = 0xFD2FB528, kSkippableMask = 0xFFFFFFF0, kSkippable = 0x184D2A50;
constexpr std::size_t kBlockMax = 128 * 1024;

constexpr std::array<std::uint32_t, 36> kLLBase{0,  1,  2,  3,  4,  5,   6,   7,   8,   9,    10,   11,
                                                12, 13, 14, 15, 16, 18,  20,  22,  24,  28,   32,   40,
                                                48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536};
constexpr std::array<std::uint8_t, 36> kLLBits{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  1,  1,
                                               1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
constexpr std::array<std::uint32_t, 53> kMLBase{3,  4,  5,  6,  7,  8,  9,  10,  11,  12,  13,   14,   15,   16,
                                                17, 18, 19, 20, 21, 22, 23, 24,  25,  26,  27,   28,   29,   30,
                                                31, 32, 33, 34, 35, 37, 39, 41,  43,  47,  51,   59,   67,   83,
                                                99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539};
constexpr std::array<std::uint8_t, 53> kMLBits{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
                                               2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
constexpr std::array<std::int16_t, 36> kLLDefault{4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2,
                                                  2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1};
constexpr std::array<std::int16_t, 53> kMLDefault{1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                                  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1};
constexpr std::array<std::int16_t, 29> kOFDefault{1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1,
                                                  1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1};

template <class A>
constexpr int abs_sum(const A& a) {
    int s = 0;
    for (auto v : a) s += v < 0 ? -v : v;
    return s;
}
static_assert(abs_sum(kLLDefault) == 64 && abs_sum(kMLDefault) == 64 && abs_sum(kOFDefault) == 32);

constexpr int highbit(std::uint64_t x) { return 63 - std::countl_zero(x); }

std::uint64_t le(Bytes d, std::size_t pos, std::size_t n) {
    if (pos > d.size() || n > d.size() - pos) zerr("truncated input");
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) v |= static_cast<std::uint64_t>(d[pos + i]) << (8 * i);
    return v;
}

/// Backward bitstream: reads start at the end marker and move toward the stream start;
/// reading past the start yields zero bits and drives `bits` negative (ZSTD_MINI_SPEC §2).
class BackwardBits {
public:
    explicit BackwardBits(Bytes stream) : s_(stream) {
        if (s_.empty()) zerr("empty bitstream");
        if (s_.back() == 0) zerr("bitstream end marker missing");
        bits = static_cast<std::int64_t>(8 * (s_.size() - 1)) + highbit(s_.back());
    }
    [[nodiscard]] std::uint64_t peek(int n) const {
        std::int64_t hi = bits, lo = hi - n;
        if (n == 0 || hi <= 0) return 0;
        if (lo < 0) return window(0, hi) << (-lo);
        return window(lo, hi);
    }
    std::uint64_t read(int n) {
        auto v = peek(n);
        bits -= n;
        return v;
    }
    std::int64_t bits;

private:
    [[nodiscard]] std::uint64_t window(std::int64_t lo, std::int64_t hi) const {
        auto last = static_cast<std::size_t>(hi - 1) >> 3;
        std::uint64_t w = 0;
        std::int64_t base = 0;
        if (last >= 7) {
            w = load_le<std::uint64_t>(s_.data() + last - 7);
            base = static_cast<std::int64_t>(last - 7) * 8;
        } else {
            for (std::size_t i = last + 1; i-- > 0;) w = w << 8 | s_[i];
        }
        return (w >> (lo - base)) & ((1ULL << (hi - lo)) - 1);
    }
    Bytes s_;
};

struct FseCell {
    std::uint8_t symbol = 0, bits = 0;
    std::uint16_t base = 0;
};

struct FseTable {
    std::array<FseCell, 512> cells{};
    int log = 0;
    bool valid = false;

    void build(std::span<const std::int16_t> probs, int accuracy_log) {
        int size = 1 << accuracy_log, high = size - 1;
        std::array<std::uint8_t, 512> symbol_at{};
        std::array<std::uint16_t, 256> counter{};
        for (std::size_t s = 0; s < probs.size(); ++s) {
            if (probs[s] == -1) {
                if (high < 0) zerr("corrupt FSE distribution");
                symbol_at[static_cast<std::size_t>(high--)] = static_cast<std::uint8_t>(s);
                counter[s] = 1;
            } else {
                counter[s] = static_cast<std::uint16_t>(probs[s]);
            }
        }
        int step = (size >> 1) + (size >> 3) + 3, mask = size - 1, pos = 0;
        for (std::size_t s = 0; s < probs.size(); ++s)
            for (int k = 0; k < probs[s]; ++k) {
                symbol_at[static_cast<std::size_t>(pos)] = static_cast<std::uint8_t>(s);
                do pos = (pos + step) & mask;
                while (pos > high);
            }
        if (pos != 0) zerr("corrupt FSE distribution");
        for (int cell = 0; cell < size; ++cell) {
            auto s = symbol_at[static_cast<std::size_t>(cell)];
            std::uint32_t x = counter[s]++;
            int nb = accuracy_log - highbit(x);
            cells[static_cast<std::size_t>(cell)] = {s, static_cast<std::uint8_t>(nb),
                                                     static_cast<std::uint16_t>((x << nb) - static_cast<std::uint32_t>(size))};
        }
        log = accuracy_log;
        valid = true;
    }

    void rle(std::uint8_t symbol) {
        cells[0] = {symbol, 0, 0};
        log = 0;
        valid = true;
    }
};

/// FSE table description (forward bitstream). Returns the byte position after it.
std::size_t read_fse_description(Bytes d, std::size_t pos, std::size_t limit, int max_symbol, int max_log,
                                 std::vector<std::int16_t>& probs, int& accuracy_log) {
    std::size_t bitpos = pos * 8;
    auto bits = [&](int n) {
        std::uint32_t v = 0;
        for (int i = 0; i < n; ++i) {
            std::size_t p = bitpos + static_cast<std::size_t>(i);
            if ((p >> 3) < limit) v |= static_cast<std::uint32_t>((d[p >> 3] >> (p & 7)) & 1) << i;
        }
        return v;
    };
    accuracy_log = static_cast<int>(bits(4)) + 5;
    bitpos += 4;
    if (accuracy_log > max_log) zerr("FSE accuracy log too large");
    int remaining = (1 << accuracy_log) + 1, threshold = 1 << accuracy_log, nbits = accuracy_log + 1;
    probs.clear();
    auto push = [&](int p) {
        if (static_cast<int>(probs.size()) > max_symbol) zerr("FSE description has too many symbols");
        probs.push_back(static_cast<std::int16_t>(p));
    };
    while (remaining > 1) {
        int biggest = 2 * threshold - 1 - remaining;
        int value;
        if (auto low = static_cast<int>(bits(nbits - 1)); low < biggest) {
            value = low;
            bitpos += static_cast<std::size_t>(nbits - 1);
        } else {
            value = static_cast<int>(bits(nbits));
            bitpos += static_cast<std::size_t>(nbits);
            if (value >= threshold) value -= biggest;
        }
        int prob = value - 1;
        push(prob);
        remaining -= prob < 0 ? -prob : prob;
        if (prob == 0) {
            for (;;) {
                auto repeat = bits(2);
                bitpos += 2;
                for (std::uint32_t k = 0; k < repeat; ++k) push(0);
                if (repeat != 3) break;
            }
        }
        while (remaining < threshold) {
            --nbits;
            threshold >>= 1;
        }
    }
    if (remaining != 1 || static_cast<int>(probs.size()) > max_symbol + 1) zerr("corrupt FSE description");
    std::size_t end = (bitpos + 7) >> 3;
    if (end > limit) zerr("FSE description overruns its section");
    return end;
}

struct HuffmanTable {
    struct Cell {
        std::uint8_t symbol = 0, bits = 0;
    };
    std::array<Cell, 2048> cells{};
    int max_bits = 0;
    bool valid = false;

    void build(std::vector<std::uint8_t> weights) {
        if (weights.size() > 255) zerr("too many Huffman weights");
        std::uint32_t total = 0;
        for (auto w : weights) {
            if (w > 11) zerr("Huffman weight too large");
            if (w) total += 1u << (w - 1);
        }
        if (!total) zerr("empty Huffman table");
        max_bits = highbit(total) + 1;
        if (max_bits > 11) zerr("Huffman code too long");
        std::uint32_t rest = (1u << max_bits) - total;
        if (!std::has_single_bit(rest)) zerr("corrupt Huffman weights");
        weights.push_back(static_cast<std::uint8_t>(highbit(rest) + 1));
        std::array<std::uint32_t, 13> next{};
        for (std::uint32_t w = 1, start = 0; w <= static_cast<std::uint32_t>(max_bits); ++w) {
            next[w] = start;
            start += static_cast<std::uint32_t>(std::count(weights.begin(), weights.end(), w)) << (w - 1);
        }
        for (std::size_t sym = 0; sym < weights.size(); ++sym) {
            auto w = weights[sym];
            if (!w) continue;
            for (std::uint32_t i = 0; i < (1u << (w - 1)); ++i)
                cells[next[w] + i] = {static_cast<std::uint8_t>(sym), static_cast<std::uint8_t>(max_bits + 1 - w)};
            next[w] += 1u << (w - 1);
        }
        valid = true;
    }

    void decode_stream(Bytes stream, std::span<std::uint8_t> out) const {
        BackwardBits br(stream);
        for (auto& o : out) {
            const auto& cell = cells[br.peek(max_bits)];
            o = cell.symbol;
            br.bits -= cell.bits;
        }
        if (br.bits != 0) zerr("Huffman stream not fully consumed");
    }
};

class FrameDecoder {
public:
    FrameDecoder(Bytes in, std::vector<std::uint8_t>& out) : in_(in), out_(out), literals_(kBlockMax) {}

    std::size_t decode(std::size_t pos) {
        auto fhd = static_cast<std::uint8_t>(le(in_, pos++, 1));
        int fcs_flag = fhd >> 6;
        bool single = fhd & 0x20, checksum = fhd & 0x04;
        if (fhd & 0x08) zerr("reserved frame header bit set");
        if (!single) le(in_, pos++, 1);  // Window_Descriptor: validation only
        constexpr std::array<std::size_t, 4> kDid{0, 1, 2, 4};
        std::size_t did = kDid[fhd & 3];
        if (did && le(in_, pos, did) != 0) zerr("zstd dictionaries are not supported");
        pos += did;
        std::array<std::size_t, 4> fcs_sizes{single ? 1u : 0u, 2, 4, 8};
        std::optional<std::uint64_t> content_size;
        if (std::size_t n = fcs_sizes[static_cast<std::size_t>(fcs_flag)]) {
            content_size = le(in_, pos, n) + (n == 2 ? 256 : 0);
            pos += n;
            if (*content_size > kMaxDecompressed) zerr("decompressed size limit exceeded");
            // A bounded hint: hostile sizes only cost what the input could plausibly expand to.
            out_.reserve(out_.size() + static_cast<std::size_t>(std::min<std::uint64_t>(*content_size, (in_.size() - pos) * 64 + 4096)));
        }
        frame_start_ = out_.size();
        rep_ = {1, 4, 8};
        huffman_.valid = ll_.valid = of_.valid = ml_.valid = false;
        for (bool last = false; !last;) {
            auto header = static_cast<std::uint32_t>(le(in_, pos, 3));
            pos += 3;
            last = header & 1;
            auto type = (header >> 1) & 3;
            std::size_t size = header >> 3;
            if (size > kBlockMax) zerr("block too large");
            switch (type) {
                case 0:
                    if (size > in_.size() - pos) zerr("truncated raw block");
                    grow(size);
                    out_.insert(out_.end(), in_.begin() + static_cast<std::ptrdiff_t>(pos),
                                in_.begin() + static_cast<std::ptrdiff_t>(pos + size));
                    pos += size;
                    break;
                case 1:
                    grow(size);
                    out_.insert(out_.end(), size, static_cast<std::uint8_t>(le(in_, pos, 1)));
                    pos += 1;
                    break;
                case 2: {
                    if (size > in_.size() - pos) zerr("truncated compressed block");
                    auto block = in_.subspan(pos, size);
                    auto [lit, used] = literals(block);
                    sequences(block, used, lit);
                    pos += size;
                    break;
                }
                default: zerr("reserved block type");
            }
        }
        if (content_size && out_.size() - frame_start_ != *content_size) zerr("frame content size mismatch");
        if (checksum) {
            auto expected = static_cast<std::uint32_t>(le(in_, pos, 4));
            pos += 4;
            if (static_cast<std::uint32_t>(xxh64(Bytes(out_).subspan(frame_start_))) != expected)
                zerr("content checksum mismatch");
        }
        return pos;
    }

private:
    void grow(std::size_t n) const {
        if (n > kMaxDecompressed - out_.size()) zerr("decompressed size limit exceeded");
    }

    /// Literals section: returns the literals and the bytes it occupied.
    std::pair<Bytes, std::size_t> literals(Bytes block) {
        if (block.empty()) zerr("missing literals section");
        auto b0 = block[0];
        int type = b0 & 3, format = (b0 >> 2) & 3;
        if (type == 0 || type == 1) {
            std::size_t size, pos;
            if (format == 0 || format == 2) size = b0 >> 3, pos = 1;
            else if (format == 1) size = (b0 >> 4) + (le(block, 1, 1) << 4), pos = 2;
            else size = (b0 >> 4) + (le(block, 1, 1) << 4) + (le(block, 2, 1) << 12), pos = 3;
            if (type == 0) {
                if (size > block.size() - pos) zerr("raw literals overrun block");
                return {block.subspan(pos, size), pos + size};
            }
            if (pos >= block.size()) zerr("RLE literals overrun block");
            if (size > kBlockMax) zerr("literals too large");
            std::fill_n(literals_.begin(), size, block[pos]);
            return {Bytes(literals_).first(size), pos + 1};
        }
        constexpr std::array<int, 4> kStreams{1, 4, 4, 4}, kHeader{3, 3, 4, 5}, kWidth{10, 10, 14, 18};
        auto f = static_cast<std::size_t>(format);
        auto header_len = static_cast<std::size_t>(kHeader[f]);
        auto h = le(block, 0, header_len);
        std::uint64_t mask = (1ULL << kWidth[f]) - 1;
        auto regenerated = static_cast<std::size_t>((h >> 4) & mask);
        auto compressed = static_cast<std::size_t>((h >> (4 + kWidth[f])) & mask);
        if (compressed > block.size() - header_len) zerr("compressed literals overrun block");
        if (regenerated > kBlockMax) zerr("literals too large");
        auto section = block.subspan(header_len, compressed);
        std::size_t pos = 0;
        if (type == 2) pos = huffman_description(section);
        else if (!huffman_.valid) zerr("treeless literals without a previous Huffman table");
        auto out = std::span(literals_).first(regenerated);
        if (kStreams[f] == 1) {
            huffman_.decode_stream(section.subspan(pos), out);
        } else {
            if (section.size() - pos < 6) zerr("corrupt 4-stream literals");
            std::array<std::size_t, 4> sizes{load_le<std::uint16_t>(&section[pos]), load_le<std::uint16_t>(&section[pos + 2]),
                                             load_le<std::uint16_t>(&section[pos + 4]), 0};
            pos += 6;
            std::size_t used = sizes[0] + sizes[1] + sizes[2];
            if (used > section.size() - pos) zerr("corrupt 4-stream literals");
            sizes[3] = section.size() - pos - used;
            std::size_t quarter = (regenerated + 3) / 4;
            if (sizes[3] < 1 || regenerated < 3 * quarter) zerr("corrupt 4-stream literals");
            std::array<std::size_t, 4> counts{quarter, quarter, quarter, regenerated - 3 * quarter};
            for (std::size_t i = 0, o = 0; i < 4; o += counts[i], pos += sizes[i], ++i)
                huffman_.decode_stream(section.subspan(pos, sizes[i]), out.subspan(o, counts[i]));
        }
        return {out, header_len + compressed};
    }

    std::size_t huffman_description(Bytes section) {
        if (section.empty()) zerr("missing Huffman description");
        std::uint8_t h = section[0];
        std::vector<std::uint8_t> weights;
        std::size_t pos = 1;
        if (h < 128) {
            if (h > section.size() - 1) zerr("Huffman description overruns literals");
            std::size_t end = 1 + h;
            std::vector<std::int16_t> probs;
            int al;
            std::size_t p = read_fse_description(section, 1, end, 255, 6, probs, al);
            FseTable table;
            table.build(probs, al);
            BackwardBits br(section.subspan(p, end - p));
            std::uint32_t states[2] = {static_cast<std::uint32_t>(br.read(al)), static_cast<std::uint32_t>(br.read(al))};
            // Two interleaved states; the stream overflowing ends the list with the other state's symbol.
            for (int which = 0;; which ^= 1) {
                if (weights.size() > 255) zerr("too many Huffman weights");
                auto& cell = table.cells[states[which]];
                weights.push_back(cell.symbol);
                states[which] = cell.base + static_cast<std::uint32_t>(br.read(cell.bits));
                if (br.bits < 0) {
                    weights.push_back(table.cells[states[which ^ 1]].symbol);
                    break;
                }
            }
            pos = end;
        } else {
            std::size_t n = h - 127u, bytes = (n + 1) / 2;
            if (bytes > section.size() - 1) zerr("Huffman description overruns literals");
            for (std::size_t i = 0; i < n; ++i) {
                auto b = section[1 + i / 2];
                weights.push_back(i % 2 == 0 ? b >> 4 : b & 15);
            }
            pos = 1 + bytes;
        }
        huffman_.build(std::move(weights));
        return pos;
    }

    std::size_t sequence_table(Bytes block, std::size_t pos, int mode, int kind) {
        static constexpr std::array<std::span<const std::int16_t>, 3> kDefaults{kLLDefault, kOFDefault, kMLDefault};
        static constexpr std::array<int, 3> kDefaultLog{6, 5, 6}, kMaxSymbol{35, 31, 52}, kMaxLog{9, 8, 9};
        auto k = static_cast<std::size_t>(kind);
        FseTable& t = kind == 0 ? ll_ : kind == 1 ? of_ : ml_;
        switch (mode) {
            case 0: t.build(kDefaults[k], kDefaultLog[k]); break;
            case 1:
                if (pos >= block.size() || block[pos] > kMaxSymbol[k]) zerr("bad RLE sequence symbol");
                t.rle(block[pos++]);
                break;
            case 2: {
                std::vector<std::int16_t> probs;
                int al;
                pos = read_fse_description(block, pos, block.size(), kMaxSymbol[k], kMaxLog[k], probs, al);
                t.build(probs, al);
                break;
            }
            default:
                if (!t.valid) zerr("repeat mode without a previous table");
        }
        return pos;
    }

    void sequences(Bytes block, std::size_t pos, Bytes lit) {
        if (pos >= block.size()) zerr("missing sequences section");
        auto b0 = block[pos];
        std::size_t count = 0;
        if (b0 == 0) {
            if (pos + 1 != block.size()) zerr("data after empty sequences section");
        } else if (b0 < 128) {
            count = b0, pos += 1;
        } else if (b0 < 255) {
            count = (static_cast<std::size_t>(b0 - 128) << 8) + le(block, pos + 1, 1), pos += 2;
        } else {
            count = le(block, pos + 1, 2) + 0x7F00, pos += 3;
        }
        std::size_t li = 0;
        if (count) {
            if (pos >= block.size()) zerr("missing compression modes");
            auto modes = block[pos++];
            if (modes & 3) zerr("reserved compression-mode bits set");
            pos = sequence_table(block, pos, (modes >> 6) & 3, 0);
            pos = sequence_table(block, pos, (modes >> 4) & 3, 1);
            pos = sequence_table(block, pos, (modes >> 2) & 3, 2);
            BackwardBits br(block.subspan(pos));
            auto ll_s = static_cast<std::uint32_t>(br.read(ll_.log));
            auto of_s = static_cast<std::uint32_t>(br.read(of_.log));
            auto ml_s = static_cast<std::uint32_t>(br.read(ml_.log));
            for (std::size_t i = 0; i < count; ++i) {
                const auto &llc = ll_.cells[ll_s], &ofc = of_.cells[of_s], &mlc = ml_.cells[ml_s];
                if (ofc.symbol > 31 || mlc.symbol > 52 || llc.symbol > 35) zerr("bad sequence code");
                std::uint64_t offset_value = (1ULL << ofc.symbol) + br.read(ofc.symbol);
                std::size_t ml = kMLBase[mlc.symbol] + br.read(kMLBits[mlc.symbol]);
                std::size_t ll = kLLBase[llc.symbol] + br.read(kLLBits[llc.symbol]);
                if (i + 1 != count) {
                    ll_s = llc.base + static_cast<std::uint32_t>(br.read(llc.bits));
                    ml_s = mlc.base + static_cast<std::uint32_t>(br.read(mlc.bits));
                    of_s = ofc.base + static_cast<std::uint32_t>(br.read(ofc.bits));
                }
                if (ll > lit.size() - li) zerr("sequence consumes more literals than available");
                grow(ll);
                out_.insert(out_.end(), lit.begin() + static_cast<std::ptrdiff_t>(li),
                            lit.begin() + static_cast<std::ptrdiff_t>(li + ll));
                li += ll;
                execute_match(resolve_offset(offset_value, ll == 0), ml);
            }
            if (br.bits != 0) zerr("sequence bitstream not fully consumed");
        }
        grow(lit.size() - li);
        out_.insert(out_.end(), lit.begin() + static_cast<std::ptrdiff_t>(li), lit.end());
    }

    std::uint64_t resolve_offset(std::uint64_t value, bool no_literals) {
        if (value > 3) {
            rep_ = {value - 3, rep_[0], rep_[1]};
            return rep_[0];
        }
        switch (value - 1 + (no_literals ? 1 : 0)) {
            case 0: return rep_[0];
            case 1: rep_ = {rep_[1], rep_[0], rep_[2]}; return rep_[0];
            case 2: rep_ = {rep_[2], rep_[0], rep_[1]}; return rep_[0];
            default: rep_ = {rep_[0] - 1, rep_[0], rep_[1]}; return rep_[0];
        }
    }

    void execute_match(std::uint64_t offset, std::size_t length) {
        if (offset == 0 || offset > out_.size() - frame_start_) zerr("match offset out of range");
        grow(length);
        std::size_t src = out_.size() - static_cast<std::size_t>(offset);
        out_.resize(out_.size() + length);
        std::uint8_t* d = out_.data();
        std::size_t dst = out_.size() - length;
        if (offset >= length) std::memcpy(d + dst, d + src, length);
        else for (std::size_t k = 0; k < length; ++k) d[dst + k] = d[src + k];  // overlapping run
    }

    Bytes in_;
    std::vector<std::uint8_t>& out_;
    std::vector<std::uint8_t> literals_;
    std::size_t frame_start_ = 0;
    std::array<std::uint64_t, 3> rep_{1, 4, 8};
    HuffmanTable huffman_;
    FseTable ll_, of_, ml_;
};

}  // namespace

std::vector<std::uint8_t> zstd_decompress(Bytes in) {
    std::vector<std::uint8_t> out;
    std::size_t pos = 0;
    while (pos < in.size()) {
        auto magic = static_cast<std::uint32_t>(le(in, pos, 4));
        if ((magic & kSkippableMask) == kSkippable) {
            auto size = le(in, pos + 4, 4);
            if (size > in.size() - pos - 8) zerr("truncated skippable frame");
            pos += 8 + static_cast<std::size_t>(size);
        } else if (magic == kMagic) {
            auto frame = std::make_unique<FrameDecoder>(in, out);  // ~10 KiB of tables: keep off the stack
            pos = frame->decode(pos + 4);
        } else {
            zerr("unknown frame magic");
        }
    }
    return out;
}

}  // namespace ob
