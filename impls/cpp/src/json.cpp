#include "json.hpp"

namespace ob {
namespace {

constexpr int kMaxDepth = 128;

class Parser {
public:
    explicit Parser(std::string_view s) : s_(s) {}

    Json document() {
        Json v = value(0);
        whitespace();
        if (pos_ != s_.size()) error("trailing characters");
        return v;
    }

private:
    [[noreturn]] static void error(std::string_view what) { throw JsonParseError(std::string(what)); }
    [[nodiscard]] bool more() const { return pos_ < s_.size(); }
    [[nodiscard]] char cur() const { return s_[pos_]; }

    void whitespace() {
        while (more() && (cur() == ' ' || cur() == '\t' || cur() == '\n' || cur() == '\r')) ++pos_;
    }

    void expect(char c) {
        whitespace();
        if (!more() || cur() != c) error(std::format("expected '{}'", c));
        ++pos_;
    }

    Json value(int depth) {
        whitespace();
        if (!more()) error("unexpected end of input");
        switch (cur()) {
            case '{': return container(depth, true);
            case '[': return container(depth, false);
            case '"': return string();
            case 't': return literal("true", Json::Kind::True);
            case 'f': return literal("false", Json::Kind::False);
            case 'n': return literal("null", Json::Kind::Null);
            default: return number();
        }
    }

    Json literal(std::string_view word, Json::Kind kind) {
        if (s_.substr(pos_, word.size()) != word) error("invalid literal");
        pos_ += word.size();
        Json v;
        v.kind = kind;
        return v;
    }

    bool digit() const { return more() && cur() >= '0' && cur() <= '9'; }

    Json number() {
        std::size_t start = pos_;
        if (more() && cur() == '-') ++pos_;
        if (!digit()) error("invalid number");
        if (cur() == '0') ++pos_;
        else while (digit()) ++pos_;
        if (more() && cur() == '.') {
            ++pos_;
            if (!digit()) error("invalid fraction");
            while (digit()) ++pos_;
        }
        if (more() && (cur() == 'e' || cur() == 'E')) {
            ++pos_;
            if (more() && (cur() == '+' || cur() == '-')) ++pos_;
            if (!digit()) error("invalid exponent");
            while (digit()) ++pos_;
        }
        Json v;
        v.kind = Json::Kind::Number;
        v.raw = s_.substr(start, pos_ - start);
        return v;
    }

    unsigned hex4() {
        if (s_.size() - pos_ < 4) error("truncated \\u escape");
        unsigned v = 0;
        auto r = std::from_chars(s_.data() + pos_, s_.data() + pos_ + 4, v, 16);
        if (r.ptr != s_.data() + pos_ + 4) error("invalid \\u escape");
        pos_ += 4;
        return v;
    }

    static void put_utf8(std::string& out, std::uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | cp >> 6);
            out += static_cast<char>(0x80 | (cp & 63));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | cp >> 12);
            out += static_cast<char>(0x80 | ((cp >> 6) & 63));
            out += static_cast<char>(0x80 | (cp & 63));
        } else {
            out += static_cast<char>(0xF0 | cp >> 18);
            out += static_cast<char>(0x80 | ((cp >> 12) & 63));
            out += static_cast<char>(0x80 | ((cp >> 6) & 63));
            out += static_cast<char>(0x80 | (cp & 63));
        }
    }

    Json string() {
        std::size_t start = pos_++;
        Json v;
        v.kind = Json::Kind::String;
        std::size_t run = pos_;
        for (;;) {
            if (!more()) error("unterminated string");
            auto ch = static_cast<unsigned char>(cur());
            if (ch == '"') break;
            if (ch < 0x20) error("control character in string");
            if (ch != '\\') {
                ++pos_;
                continue;
            }
            v.text.append(s_.substr(run, pos_ - run));
            ++pos_;
            if (!more()) error("truncated escape");
            char e = s_[pos_++];
            switch (e) {
                case '"': v.text += '"'; break;
                case '\\': v.text += '\\'; break;
                case '/': v.text += '/'; break;
                case 'b': v.text += '\b'; break;
                case 'f': v.text += '\f'; break;
                case 'n': v.text += '\n'; break;
                case 'r': v.text += '\r'; break;
                case 't': v.text += '\t'; break;
                case 'u': {
                    std::uint32_t cp = hex4();
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (s_.substr(pos_, 2) != "\\u") error("lone surrogate");
                        pos_ += 2;
                        std::uint32_t lo = hex4();
                        if (lo < 0xDC00 || lo > 0xDFFF) error("invalid surrogate pair");
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        error("lone surrogate");
                    }
                    put_utf8(v.text, cp);
                    break;
                }
                default: error("invalid escape");
            }
            run = pos_;
        }
        v.text.append(s_.substr(run, pos_ - run));
        if (!valid_utf8(as_bytes(s_.substr(start + 1, pos_ - start - 1)))) error("invalid UTF-8");
        ++pos_;
        v.raw = s_.substr(start, pos_ - start);
        return v;
    }

    Json container(int depth, bool object) {
        if (depth >= kMaxDepth) error("nesting too deep");
        ++pos_;
        Json v;
        v.kind = object ? Json::Kind::Object : Json::Kind::Array;
        char close = object ? '}' : ']';
        whitespace();
        if (more() && cur() == close) {
            ++pos_;
            return v;
        }
        for (;;) {
            if (object) {
                whitespace();
                if (!more() || cur() != '"') error("expected object key");
                Json k = string();
                expect(':');
                v.members.emplace_back(std::move(k.text), value(depth + 1));
            } else {
                v.items.push_back(value(depth + 1));
            }
            whitespace();
            if (more() && cur() == ',') {
                ++pos_;
                continue;
            }
            if (more() && cur() == close) {
                ++pos_;
                return v;
            }
            error("expected ',' or a closing bracket");
        }
    }

    std::string_view s_;
    std::size_t pos_ = 0;
};

}  // namespace

const Json* Json::get(std::string_view key) const {
    const Json* found = nullptr;
    if (kind == Kind::Object)
        for (const auto& [k, v] : members)
            if (k == key) found = &v;
    return found;
}

Json parse_json(std::string_view text) { return Parser(text).document(); }

}  // namespace ob
