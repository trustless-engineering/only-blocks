import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Base64

internal class DecodeFailure(message: String) : RuntimeException(message)
internal fun requireWire(condition: Boolean, message: String = "Invalid archive data") {
    if (!condition) throw DecodeFailure(message)
}
internal typealias Obj = MutableMap<String, Any?>
internal fun obj(vararg pairs: Pair<String, Any?>): Obj = linkedMapOf(*pairs)
internal fun unsigned(value: ULong) = JsonNumber(value.toString())
internal fun utf8(bytes: ByteArray): String = Charsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()

internal class Bytes(val data: ByteArray, var pos: Int = 0, val end: Int = data.size) {
    val remaining get() = end - pos
    fun skip(n: Int) {
        requireWire(n in 0..remaining, "Truncated bytes")
        pos += n
    }
    fun u8(): Int {
        skip(1)
        return data[pos - 1].toInt() and 255
    }
    fun le(n: Int): ULong {
        var v = 0uL
        repeat(n) { v = v or (u8().toULong() shl (8 * it)) }
        return v
    }
    fun u32() = le(4).toLong()
    fun u64() = le(8)
    fun varint(): ULong {
        var value = 0uL
        repeat(10) {
            val b = u8()
            requireWire(it < 9 || b <= 1)
            value = value or ((b and 127).toULong() shl (7 * it))
            if (b < 128) return value
        }
        throw DecodeFailure("Invalid varint")
    }
    fun short(): Int {
        var value = 0
        repeat(3) {
            val b = u8()
            requireWire((it == 0 || b != 0) && (it < 2 || b < 4))
            value = value or ((b and 127) shl (7 * it))
            if (b < 128) return value
        }
        throw DecodeFailure("Invalid compact-u16")
    }
    fun count(value: ULong, limit: Int = remaining): Int {
        requireWire(value <= limit.toULong(), "Invalid length")
        return value.toInt()
    }
    fun bytes(n: Int): ByteArray {
        val start = pos
        skip(n)
        return data.copyOfRange(start, pos)
    }
    fun part(n: Int): Bytes {
        val start = pos
        skip(n)
        return Bytes(data, start, pos)
    }
    fun vector() = bytes(count(u64()))
    fun text() = utf8(vector())
    fun <T> list(read: () -> T): List<T> {
        val n = count(u64())
        val out = ArrayList<T>(minOf(n, 1024))
        repeat(n) { out.add(read()) }
        return out
    }
    fun <T> optional(read: () -> T): T? = when (if (remaining == 0) 0 else u8()) {
        0 -> null
        1 -> read()
        else -> throw DecodeFailure("Invalid option")
    }
}

internal fun ByteArray.b64() = Base64.getEncoder().encodeToString(this)
internal fun ByteArray.indicesList() = map { it.toInt() and 255 }
internal fun ByteArray.b58(): String {
    val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    val first = indexOfFirst { it != 0.toByte() }.let { if (it < 0) size else it }
    val radix = BigInteger.valueOf(58)
    var n = BigInteger(1, this)
    val out = StringBuilder()
    while (n.signum() > 0) {
        val (q, r) = n.divideAndRemainder(radix)
        out.append(alphabet[r.toInt()])
        n = q
    }
    repeat(first) { out.append('1') }
    return out.reverse().toString()
}
internal fun ByteArray.pubkey(): String {
    requireWire(size == 32)
    return b58()
}

internal fun cbor(r: Bytes, depth: Int = 0): Any? {
    requireWire(depth <= 128)
    val header = r.u8()
    val major = header ushr 5
    val info = header and 31
    val child = { cbor(r, depth + 1) }
    if (major == 7) return when (info) {
        20 -> false
        21 -> true
        22, 23 -> null
        25, 26, 27 -> {
            r.skip(1 shl (info - 24))
            // Floats occur only in ignored archive fields.
            Unit
        }
        else -> throw DecodeFailure("Unsupported CBOR simple value")
    }
    val arg = when (info) {
        in 0..23 -> info.toULong()
        in 24..27 -> {
            var n = 0uL
            repeat(1 shl (info - 24)) { n = (n shl 8) or r.u8().toULong() }
            n
        }
        31 -> {
            requireWire(major in 2..5)
            null
        }
        else -> throw DecodeFailure("Invalid CBOR argument")
    }
    fun items(read: () -> Unit) {
        if (arg != null) repeat(r.count(arg)) { read() }
        else {
            while (r.remaining > 0 && r.data[r.pos] != 0xff.toByte()) read()
            r.skip(1)
        }
    }
    return when (major) {
        0 -> arg!!
        1 -> if (arg!! <= Long.MAX_VALUE.toULong()) -1 - arg.toLong() else Unit
        2, 3 -> {
            val bytes = if (arg != null) r.bytes(r.count(arg)) else {
                val out = java.io.ByteArrayOutputStream()
                items {
                    requireWire((r.data[r.pos].toInt() and 255) ushr 5 == major &&
                        (r.data[r.pos].toInt() and 31) != 31)
                    val part = child()
                    out.write(if (part is String) part.toByteArray() else part as ByteArray)
                }
                out.toByteArray()
            }
            if (major == 2) bytes else utf8(bytes)
        }
        4 -> buildList { items { add(child()) } }
        5 -> buildMap { items { put(child(), child()) } }
        6 -> child()
        else -> throw DecodeFailure("Invalid CBOR major type")
    }
}

internal data class Cid(val key: String, val absent: Boolean = false)
internal fun cid(r: Bytes): Cid {
    val start = r.pos
    val a = r.varint()
    val b = r.varint()
    var absent = false
    if (a == 18uL && b == 32uL) r.skip(32)
    else {
        requireWire(a == 1uL)
        val code = r.varint()
        val n = r.count(r.varint(), 64)
        r.skip(n)
        absent = code == 0uL && n == 0
    }
    return Cid(String(r.data, start, r.pos - start, Charsets.ISO_8859_1), absent)
}

internal fun link(value: Any?): Cid {
    val r = Bytes(value as? ByteArray ?: throw DecodeFailure("Invalid CID link"))
    requireWire(r.u8() == 0)
    return cid(r)
}
internal fun links(value: Any?): List<Cid> = (value as? List<*>)?.map(::link).orEmpty()
internal fun Any?.node(kind: ULong): List<*> {
    val fields = this as? List<*> ?: throw DecodeFailure("Invalid node")
    requireWire(fields.firstOrNull() == kind, "Wrong node kind")
    return fields
}
internal data class NodeBytes(val data: ByteArray, val start: Int, val end: Int) {
    fun decode(): Any? {
        val r = Bytes(data, start, end)
        val v = cbor(r)
        requireWire(r.remaining == 0, "Trailing CBOR")
        return v
    }
}
internal class Car(bytes: ByteArray) {
    private val index = HashMap<String, NodeBytes>()
    val block: List<*>
    init {
        val r = Bytes(bytes)
        var first = true
        var blockSection: NodeBytes? = null
        while (r.remaining > 0) {
            val n = r.count(r.varint(), 32 shl 20)
            if (n == 0) continue
            val section = r.part(n)
            val header = first && (bytes[section.pos].toInt() and 0xe0) == 0xa0 &&
                (runCatching { NodeBytes(bytes, section.pos, section.end).decode() }.getOrNull()
                    as? Map<*, *>)?.containsKey("version") == true
            first = false
            if (header) continue
            val key = cid(section)
            val node = NodeBytes(bytes, section.pos, section.end)
            index[key.key] = node
            if (section.remaining > 1) {
                val tag = bytes[section.pos].toInt() and 255
                val extra = when (tag and 31) {
                    in 0..23, 31 -> 0
                    in 24..27 -> 1 shl ((tag and 31) - 24)
                    else -> -1
                }
                if (tag ushr 5 == 4 && extra >= 0 && section.remaining > extra + 1 &&
                    bytes[section.pos + extra + 1] == 2.toByte()) blockSection = node
            }
        }
        block = blockSection?.decode().node(2uL)
        requireWire(block.getOrNull(1) is ULong, "Missing block slot")
    }
    fun find(cid: Cid, kind: ULong): List<*>? = index[cid.key]?.decode()?.node(kind)
    fun get(cid: Cid, kind: ULong) = find(cid, kind) ?: throw DecodeFailure("Missing node")

    fun payload(value: Any?): ByteArray {
        val root = value.node(6uL)
        val expected = root.getOrNull(1) as? ULong
        val data = root.getOrNull(4) as? ByteArray ?: byteArrayOf()
        val next = links(root.getOrNull(5))
        val bytes = if (next.isEmpty()) data else {
            val visited = HashSet<String>()
            val stack = ArrayDeque(next.asReversed())
            val out = java.io.ByteArrayOutputStream()
            out.write(data)
            while (stack.isNotEmpty()) {
                val cid = stack.removeLast()
                requireWire(visited.add(cid.key), "Repeated DataFrame CID")
                val frame = get(cid, 6uL)
                val part = frame.getOrNull(4) as? ByteArray
                if (part != null) out.write(part)
                stack.addAll(links(frame.getOrNull(5)).asReversed())
            }
            out.toByteArray()
        }
        if (expected != null) requireWire(bytes.crc64() == expected || bytes.fnv() == expected,
            "DataFrame checksum mismatch")
        return bytes
    }
}
private val crcTable = List(256) { b ->
    var v = b.toULong()
    repeat(8) { v = (v shr 1) xor (if ((v and 1uL) != 0uL) 0xd800000000000000uL else 0uL) }
    v
}
private fun ByteArray.crc64(): ULong {
    var v = ULong.MAX_VALUE
    for (b in this) v = (v shr 8) xor crcTable[(v.toInt() xor b.toInt()) and 255]
    return v.inv()
}
private fun ByteArray.fnv(): ULong {
    var v = 0xcbf29ce484222325uL
    for (b in this) v = (v xor (b.toInt() and 255).toULong()) * 0x100000001b3uL
    return v
}
