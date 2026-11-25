package onlyblocks;

import java.nio.charset.StandardCharsets;
import java.util.*;
import static onlyblocks.Wire.*;

final class Json {
    record Num(String text) {
        Long unsigned() {
            if (!text.chars().allMatch(c -> c >= '0' && c <= '9')) return null;
            try { return Long.parseUnsignedLong(text); }
            catch (NumberFormatException e) { return null; }
        }
    }
    private final String text;
    private int pos;
    Json(byte[] body) { text = utf8(body); }

    Object parse() {
        var value = value(0);
        spaces();
        check(pos == text.length());
        return value;
    }
    private int peek() { return pos < text.length() ? text.charAt(pos) : -1; }
    private boolean take(char c) {
        if (peek() != c) return false;
        pos++;
        return true;
    }
    private void spaces() {
        while (peek() == ' ' || peek() == '\t' || peek() == '\r' || peek() == '\n') pos++;
    }
    private Object literal(String word, Object value) {
        check(text.startsWith(word, pos));
        pos += word.length();
        return value;
    }
    private Object value(int depth) {
        check(depth <= 128);
        spaces();
        return switch (peek()) {
            case '{' -> {
                pos++;
                var out = obj();
                spaces();
                if (!take('}')) {
                    do {
                        spaces();
                        String key = string();
                        spaces();
                        check(take(':'));
                        out.put(key, value(depth + 1));
                        spaces();
                    } while (take(','));
                    check(take('}'));
                }
                yield out;
            }
            case '[' -> {
                pos++;
                var out = new ArrayList<>();
                spaces();
                if (!take(']')) {
                    do {
                        out.add(value(depth + 1));
                        spaces();
                    } while (take(','));
                    check(take(']'));
                }
                yield out;
            }
            case '"' -> string();
            case 'n' -> literal("null", null);
            case 'f' -> literal("false", false);
            case 't' -> literal("true", true);
            default -> number();
        };
    }
    private void digits() {
        int start = pos;
        while (peek() >= '0' && peek() <= '9') pos++;
        check(pos > start);
    }
    private Num number() {
        int start = pos;
        take('-');
        if (!take('0')) digits();
        if (take('.')) digits();
        if (take('e') || take('E')) {
            if (!take('+')) take('-');
            digits();
        }
        return new Num(text.substring(start, pos));
    }
    private String string() {
        check(take('"'));
        var out = new StringBuilder();
        while (pos < text.length()) {
            char c = text.charAt(pos++);
            if (c == '"') return out.toString();
            check(c >= 32);
            if (c == '\\') {
                check(pos < text.length());
                c = switch (text.charAt(pos++)) {
                    case '"' -> '"';
                    case '/' -> '/';
                    case '\\' -> '\\';
                    case 'b' -> '\b';
                    case 'f' -> '\f';
                    case 'n' -> '\n';
                    case 'r' -> '\r';
                    case 't' -> '\t';
                    case 'u' -> unicode();
                    default -> throw new BadData("Invalid JSON escape");
                };
            }
            out.append(c);
        }
        throw new BadData("Unclosed JSON string");
    }
    private char unicode() {
        check(text.length() - pos >= 4);
        int code = 0;
        for (int i = 0; i < 4; i++) {
            char c = text.charAt(pos++);
            int digit = c >= '0' && c <= '9' ? c - '0' :
                        c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                        c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
            check(digit >= 0);
            code = code * 16 + digit;
        }
        return (char) code;
    }
    static byte[] encode(Object value) {
        var out = new StringBuilder();
        emit(out, value);
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }
    private static void quote(StringBuilder out, String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '"') out.append('\\').append(c);
            else if (c < ' ' || Character.isSurrogate(c)) {
                out.append("\\u");
                for (int shift = 12; shift >= 0; shift -= 4) out.append(Character.forDigit((c >>> shift) & 15, 16));
            } else out.append(c);
        }
        out.append('"');
    }
    private static void emit(StringBuilder out, Object value) {
        if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (var e : map.entrySet()) {
                if (!first) out.append(',');
                first = false;
                quote(out, (String) e.getKey());
                out.append(':');
                emit(out, e.getValue());
            }
            out.append('}');
        } else if (value instanceof List<?> list) {
            out.append('[');
            boolean first = true;
            for (Object v : list) {
                if (!first) out.append(',');
                first = false;
                emit(out, v);
            }
            out.append(']');
        } else if (value instanceof String s) quote(out, s);
        else if (value instanceof Num n) out.append(n.text);
        else if (value == null || value instanceof Boolean || value instanceof Number) out.append(value);
        else throw new IllegalArgumentException("Unsupported JSON value");
    }
}
