internal data class JsonNumber(val text: String) {
    fun asUnsigned(): ULong? = if (text.all { it in '0'..'9' }) text.toULongOrNull() else null
}

internal class Json(private val input: String) {
    private var pos = 0
    private fun peek() = input.getOrNull(pos)
    private fun spaces() {
        while (true) when (peek()) {
            ' ', '\t', '\r', '\n' -> pos++
            else -> return
        }
    }
    private fun take(c: Char): Boolean {
        if (peek() != c) return false
        pos++
        return true
    }
    private fun expect(c: Char) { requireWire(take(c), "Expected JSON character") }
    private fun literal(text: String, result: Any?): Any? {
        requireWire(input.startsWith(text, pos))
        pos += text.length
        return result
    }

    fun parse(): Any? {
        val result = value(0)
        spaces()
        requireWire(pos == input.length)
        return result
    }
    private fun value(depth: Int): Any? {
        spaces()
        requireWire(depth <= 128, "JSON nesting limit")
        return when (peek()) {
            '"' -> string()
            '{' -> {
                pos++
                spaces()
                val result = obj()
                if (!take('}')) {
                    do {
                        spaces()
                        val key = string()
                        spaces()
                        expect(':')
                        result[key] = value(depth + 1)
                        spaces()
                    } while (take(','))
                    expect('}')
                }
                result
            }
            '[' -> {
                pos++
                spaces()
                val result = ArrayList<Any?>()
                if (!take(']')) {
                    do {
                        result.add(value(depth + 1))
                        spaces()
                    } while (take(','))
                    expect(']')
                }
                result
            }
            'n' -> literal("null", null)
            't' -> literal("true", true)
            'f' -> literal("false", false)
            '-', in '0'..'9' -> number()
            else -> throw DecodeFailure("Invalid JSON value")
        }
    }
    private fun digits() {
        val start = pos
        while (peek()?.let { it in '0'..'9' } == true) pos++
        requireWire(pos > start)
    }
    private fun number(): JsonNumber {
        val start = pos
        take('-')
        if (!take('0')) digits()
        if (take('.')) digits()
        if (take('e') || take('E')) {
            if (!take('+')) take('-')
            digits()
        }
        return JsonNumber(input.substring(start, pos))
    }
    private fun string(): String {
        expect('"')
        val out = StringBuilder()
        while (pos < input.length) {
            val c = input[pos++]
            when (c) {
                '"' -> return out.toString()
                '\\' -> {
                    requireWire(pos < input.length)
                    when (val e = input[pos++]) {
                        '"', '\\', '/' -> out.append(e)
                        'b' -> out.append('\b')
                        'f' -> out.append('\u000c')
                        'n' -> out.append('\n')
                        'r' -> out.append('\r')
                        't' -> out.append('\t')
                        'u' -> {
                            requireWire(input.length - pos >= 4)
                            var code = 0
                            repeat(4) {
                                val digit = input[pos++]
                                val value = when (digit) {
                                    in '0'..'9' -> digit - '0'
                                    in 'a'..'f' -> digit - 'a' + 10
                                    in 'A'..'F' -> digit - 'A' + 10
                                    else -> throw DecodeFailure("Invalid escape")
                                }
                                code = code * 16 + value
                            }
                            out.append(code.toChar())
                        }
                        else -> throw DecodeFailure("Invalid escape")
                    }
                }
                else -> {
                    requireWire(c >= ' ')
                    out.append(c)
                }
            }
        }
        throw DecodeFailure("Unclosed JSON string")
    }
}

internal fun encodeJson(value: Any?): ByteArray = buildString {
    fun quote(s: String) {
        append('"')
        for (c in s) when (c) {
            '"', '\\' -> { append('\\'); append(c) }
            '\b' -> append("\\b")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (c < ' ' || c.isSurrogate()) {
                append("\\u")
                append(c.code.toString(16).padStart(4, '0'))
            } else append(c)
        }
        append('"')
    }
    fun emit(v: Any?) {
        when (v) {
            null -> append("null")
            is Boolean, is Number -> append(v)
            is JsonNumber -> append(v.text)
            is String -> quote(v)
            is Map<*, *> -> {
                append('{')
                v.entries.forEachIndexed { i, (key, x) ->
                    if (i > 0) append(',')
                    quote(key as String)
                    append(':')
                    emit(x)
                }
                append('}')
            }
            is List<*> -> {
                append('[')
                v.forEachIndexed { i, x ->
                    if (i > 0) append(',')
                    emit(x)
                }
                append(']')
            }
            else -> error("Unexpected JSON value")
        }
    }
    emit(value)
}.toByteArray()
