/** Dictionary-free RFC 8878 decoder. The state shared across blocks is reset at each frame. */
internal object Zstd {
    private const val MAX_OUTPUT = 512 shl 20
    private const val MAX_BLOCK = 128 shl 10
    private val LL_BASE = intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
           16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
           8192, 16384, 32768, 65536)
    private val LL_BITS = intArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
           13, 14, 15, 16)
    private val ML_BASE = intArrayOf(3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
           19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
           35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
           4099, 8195, 16387, 32771, 65539)
    private val ML_BITS = intArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
           12, 13, 14, 15, 16)
    private val LL_DEFAULT = intArrayOf(4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
              2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
              -1, -1, -1, -1)
    private val ML_DEFAULT = intArrayOf(1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
              -1, -1, -1, -1, -1)
    private val OF_DEFAULT = intArrayOf(1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1)

    private fun high(v: Int) = 31 - v.countLeadingZeroBits()
    private class Backward(val r: Bytes) {
        private val last = if (r.remaining > 0) r.data[r.end - 1].toInt() and 255 else 0
        init { requireWire(last != 0, "Missing Zstd bitstream marker") }
        var bits = 8 * (r.remaining - 1) + high(last)
        fun peek(n: Int): Int {
            val low = bits - n
            if (n == 0 || bits <= 0) return 0
            val from = maxOf(0, low)
            val first = from ushr 3
            val last = (bits - 1) ushr 3
            var word = 0L
            for (i in first..last) word = word or ((r.data[r.pos + i].toLong() and 255) shl (8 * (i - first)))
            val mask = (1L shl (bits - from)) - 1
            return (((word ushr (from and 7)) and mask) shl (from - low)).toInt()
        }
        fun read(n: Int) = peek(n).also { bits -= n }
    }

    private data class Cell(val symbol: Int, val bits: Int, val base: Int)
    private data class Table(val cells: List<Cell>, val log: Int)
    private fun fse(prob: IntArray, log: Int): Table {
        val size = 1 shl log
        requireWire(prob.sumOf { kotlin.math.abs(it) } == size)
        val symbols = IntArray(size)
        val counters = prob.copyOf()
        var high = size - 1
        for (s in prob.indices) if (prob[s] == -1) {
            symbols[high--] = s
            counters[s] = 1
        }
        val step = (size ushr 1) + (size ushr 3) + 3
        var pos = 0
        for (s in prob.indices) repeat(maxOf(prob[s], 0)) {
            symbols[pos] = s
            do { pos = (pos + step) and (size - 1) } while (pos > high)
        }
        requireWire(pos == 0)
        return Table(symbols.map { s ->
            val n = counters[s]++
            val bits = log - high(n)
            Cell(s, bits, (n shl bits) - size)
        }, log)
    }

    private fun readFse(r: Bytes, maxSymbol: Int, maxLog: Int): Table {
        var cursor = r.pos * 8
        fun peek(n: Int): Int {
            var value = 0
            repeat(n) {
                val p = cursor + it
                if ((p ushr 3) < r.end) value = value or (((r.data[p ushr 3].toInt() ushr (p and 7)) and 1) shl it)
            }
            return value
        }
        fun read(n: Int): Int {
            val v = peek(n)
            cursor += n
            requireWire(cursor <= r.end * 8)
            return v
        }
        val log = read(4) + 5
        requireWire(log <= maxLog)
        var threshold = 1 shl log
        var remaining = threshold + 1
        var width = log + 1
        val prob = ArrayList<Int>()
        while (remaining > 1) {
            requireWire(prob.size <= maxSymbol)
            val max = 2 * threshold - 1 - remaining
            val low = peek(width - 1)
            val value = if (low < max) read(width - 1) else read(width).let { if (it >= threshold) it - max else it }
            val p = value - 1
            prob.add(p)
            remaining -= kotlin.math.abs(p)
            requireWire(remaining >= 1)
            if (p == 0) do {
                val count = read(2)
                repeat(count) { prob.add(0) }
                requireWire(prob.size <= maxSymbol + 1)
            } while (count == 3)
            while (remaining < threshold) {
                width--
                threshold = threshold ushr 1
            }
        }
        r.pos = (cursor + 7) ushr 3
        return fse(prob.toIntArray(), log)
    }

    private fun readHuffman(r: Bytes): Table {
        val header = r.u8()
        val weights = ArrayList<Int>()
        if (header >= 128) {
            val count = header - 127
            val packed = r.bytes((count + 1) / 2)
            repeat(count) { i -> weights.add((packed[i / 2].toInt() ushr (if (i % 2 == 0) 4 else 0)) and 15) }
        } else {
            val part = r.part(header)
            val fse = readFse(part, 255, 6)
            val br = Backward(part)
            val states = IntArray(2) { br.read(fse.log) }
            requireWire(br.bits >= 0)
            var i = 0
            while (true) {
                requireWire(weights.size < 255)
                val cell = fse.cells[states[i]]
                weights.add(cell.symbol)
                states[i] = cell.base + br.read(cell.bits)
                i = 1 - i
                if (br.bits < 0) {
                    weights.add(fse.cells[states[i]].symbol)
                    break
                }
            }
        }
        requireWire(weights.size <= 255 && weights.all { it in 0..11 })
        val total = weights.sumOf { if (it == 0) 0 else 1 shl (it - 1) }
        requireWire(total > 0)
        val log = high(total) + 1
        val rest = (1 shl log) - total
        requireWire(log <= 11 && rest.countOneBits() == 1)
        weights.add(high(rest) + 1)
        val cells = ArrayList<Cell>(1 shl log)
        for (w in 1..log) for ((symbol, weight) in weights.withIndex()) if (w == weight) {
            repeat(1 shl (w - 1)) { cells.add(Cell(symbol, log + 1 - w, 0)) }
        }
        return Table(cells, log)
    }

    private class Frame(val start: Int, val window: Long) {
        val rep = longArrayOf(1, 4, 8)
        val tables = arrayOfNulls<Table>(3)
        var huffman: Table? = null
    }

    private fun literals(r: Bytes, frame: Frame): ByteArray {
        val first = r.u8()
        val type = first and 3
        val format = (first ushr 2) and 3
        if (type < 2) {
            val size = when (format) {
                0, 2 -> first ushr 3
                1 -> (first ushr 4) + (r.u8() shl 4)
                else -> (first ushr 4) + (r.le(2).toInt() shl 4)
            }
            requireWire(size <= MAX_BLOCK)
            return if (type == 0) r.bytes(size) else ByteArray(size).apply { fill(r.u8().toByte()) }
        }
        val width = when (format) { 0, 1 -> 10; 2 -> 14; else -> 18 }
        val size = when (format) { 0, 1 -> 3; 2 -> 4; else -> 5 }
        val header = first.toLong() or (r.le(size - 1).toLong() shl 8)
        val regenerated = ((header ushr 4).toInt() and ((1 shl width) - 1))
        requireWire(regenerated <= MAX_BLOCK)
        val part = r.part((header ushr (4 + width)).toInt())
        val table = if (type == 2) readHuffman(part).also { frame.huffman = it }
            else frame.huffman ?: throw DecodeFailure("Missing previous Huffman table")
        val out = ByteArray(regenerated)
        fun stream(input: Bytes, start: Int, count: Int) {
            val br = Backward(input)
            for (i in start until start + count) {
                val cell = table.cells[br.peek(table.log)]
                br.bits -= cell.bits
                requireWire(br.bits >= 0)
                out[i] = cell.symbol.toByte()
            }
            requireWire(br.bits == 0, "Trailing Huffman bits")
        }
        if (format == 0) stream(part, 0, regenerated)
        else {
            val sizes = IntArray(3) { part.le(2).toInt() }
            val quarter = (regenerated + 3) / 4
            requireWire(regenerated >= 3 * quarter)
            for (i in 0..2) stream(part.part(sizes[i]), i * quarter, quarter)
            stream(part, 3 * quarter, regenerated - 3 * quarter)
        }
        return out
    }

    private val predefined = arrayOf(fse(LL_DEFAULT, 6), fse(OF_DEFAULT, 5), fse(ML_DEFAULT, 6))
    private val maxSymbol = intArrayOf(35, 31, 52)
    private val maxLog = intArrayOf(9, 8, 9)

    private class Output {
        var bytes = ByteArray(256)
        var size = 0
        fun reserve(n: Int) {
            requireWire(n in 0..MAX_OUTPUT - size, "Zstd output limit exceeded")
            if (size + n > bytes.size) bytes = bytes.copyOf(maxOf(size + n, bytes.size * 2))
        }
        fun append(data: ByteArray, start: Int, count: Int) {
            reserve(count)
            data.copyInto(bytes, size, start, start + count)
            size += count
        }
        fun repeatByte(value: Byte, n: Int) {
            reserve(n)
            bytes.fill(value, size, size + n)
            size += n
        }
        fun match(offset: Int, n: Int) {
            reserve(n)
            repeat(n) {
                bytes[size] = bytes[size - offset]
                size++
            }
        }
    }

    private fun compressed(r: Bytes, out: Output, frame: Frame, blockLimit: Int) {
        val literals = literals(r, frame)
        val start = out.size
        val first = r.u8()
        if (first == 0) {
            requireWire(r.remaining == 0 && literals.size <= blockLimit)
            out.append(literals, 0, literals.size)
            return
        }
        val count = when {
            first < 128 -> first
            first < 255 -> ((first - 128) shl 8) + r.u8()
            else -> r.le(2).toInt() + 0x7f00
        }
        val modes = r.u8()
        requireWire(modes and 3 == 0)
        val tables = Array(3) { i ->
            val table = when ((modes ushr (6 - 2 * i)) and 3) {
                0 -> predefined[i]
                1 -> {
                    val code = r.u8()
                    requireWire(code <= maxSymbol[i])
                    Table(listOf(Cell(code, 0, 0)), 0)
                }
                2 -> readFse(r, maxSymbol[i], maxLog[i])
                else -> frame.tables[i] ?: throw DecodeFailure("Missing previous FSE table")
            }
            frame.tables[i] = table
            table
        }
        val bits = Backward(r)
        val states = IntArray(3) { bits.read(tables[it].log) }
        var literal = 0
        repeat(count) { seq ->
            val llCell = tables[0].cells[states[0]]
            val ofCell = tables[1].cells[states[1]]
            val mlCell = tables[2].cells[states[2]]
            val offsetValue = (1L shl ofCell.symbol) + bits.read(ofCell.symbol)
            val ml = ML_BASE[mlCell.symbol] + bits.read(ML_BITS[mlCell.symbol])
            val ll = LL_BASE[llCell.symbol] + bits.read(LL_BITS[llCell.symbol])
            requireWire(bits.bits >= 0 && literal + ll <= literals.size && out.size - start + ll + ml <= blockLimit)
            out.append(literals, literal, ll)
            literal += ll
            val rep = frame.rep
            val index = if (offsetValue > 3) 3 else offsetValue.toInt() - 1 + if (ll == 0) 1 else 0
            val offset = if (offsetValue > 3) offsetValue - 3 else if (index == 3) rep[0] - 1 else rep[index]
            if (index != 0) {
                if (index >= 2) rep[2] = rep[1]
                rep[1] = rep[0]
                rep[0] = offset
            }
            requireWire(offset in 1..minOf(frame.window, (out.size - frame.start).toLong()))
            out.match(offset.toInt(), ml)
            if (seq + 1 < count) {
                states[0] = llCell.base + bits.read(llCell.bits)
                states[2] = mlCell.base + bits.read(mlCell.bits)
                states[1] = ofCell.base + bits.read(ofCell.bits)
                requireWire(bits.bits >= 0)
            }
        }
        requireWire(bits.bits == 0 && out.size - start + literals.size - literal <= blockLimit)
        out.append(literals, literal, literals.size - literal)
    }

    fun decode(bytes: ByteArray): ByteArray {
        val r = Bytes(bytes)
        val out = Output()
        while (r.remaining > 0) {
            val magic = r.le(4)
            if (magic and 0xfffffff0uL == 0x184d2a50uL) {
                r.skip(r.count(r.le(4)))
                continue
            }
            requireWire(magic == 0xfd2fb528uL, "Unknown Zstd magic")
            val descriptor = r.u8()
            requireWire(descriptor and 8 == 0)
            val single = descriptor and 32 != 0
            val window = if (single) null else r.u8().let {
                val base = 1L shl (10 + (it ushr 3))
                base + (base ushr 3) * (it and 7)
            }
            val did = intArrayOf(0, 1, 2, 4)[descriptor and 3]
            requireWire(r.le(did) == 0uL, "Zstd dictionaries unsupported")
            val width = intArrayOf(if (single) 1 else 0, 2, 4, 8)[descriptor ushr 6]
            val contentSize = if (width == 0) null else r.le(width).let { it + if (width == 2) 256uL else 0uL }
            requireWire(contentSize == null || contentSize <= (MAX_OUTPUT - out.size).toULong())
            val frame = Frame(out.size, window ?: contentSize!!.toLong())
            val blockLimit = minOf(MAX_BLOCK.toLong(), frame.window).toInt()
            do {
                val header = r.le(3).toInt()
                val n = header ushr 3
                requireWire(n <= blockLimit)
                when ((header ushr 1) and 3) {
                    0 -> {
                        out.append(r.data, r.pos, r.part(n).remaining)
                    }
                    1 -> out.repeatByte(r.u8().toByte(), n)
                    2 -> compressed(r.part(n), out, frame, blockLimit)
                    else -> throw DecodeFailure("Reserved Zstd block type")
                }
            } while (header and 1 == 0)
            requireWire(contentSize == null || contentSize == (out.size - frame.start).toULong())
            if (descriptor and 4 != 0) requireWire(r.u32().toInt() == xxh64(out.bytes, frame.start, out.size).toInt(),
                "Zstd checksum mismatch")
        }
        return out.bytes.copyOf(out.size)
    }

    private val p1 = 0x9e3779b185ebca87uL.toLong()
    private val p2 = 0xc2b2ae3d27d4eb4fuL.toLong()
    private const val p3 = 0x165667b19e3779f9L
    private val p4 = 0x85ebca77c2b2ae63uL.toLong()
    private const val p5 = 0x27d4eb2f165667c5L
    private fun round(a: Long, lane: Long) = (a + lane * p2).rotateLeft(31) * p1
    private fun xxh64(data: ByteArray, start: Int, end: Int): Long {
        val r = Bytes(data, start, end)
        var h = p5
        if (r.remaining >= 32) {
            val lanes = longArrayOf(p1 + p2, p2, 0, -p1)
            while (r.remaining >= 32) for (i in lanes.indices) lanes[i] = round(lanes[i], r.u64().toLong())
            h = lanes[0].rotateLeft(1) + lanes[1].rotateLeft(7) + lanes[2].rotateLeft(12) + lanes[3].rotateLeft(18)
            for (lane in lanes) h = (h xor round(0, lane)) * p1 + p4
        }
        h += end - start
        while (r.remaining >= 8) h = (h xor round(0, r.u64().toLong())).rotateLeft(27) * p1 + p4
        if (r.remaining >= 4) h = (h xor (r.u32() * p1)).rotateLeft(23) * p2 + p3
        while (r.remaining > 0) h = (h xor (r.u8() * p5)).rotateLeft(11) * p1
        h = (h xor (h ushr 33)) * p2
        h = (h xor (h ushr 29)) * p3
        return h xor (h ushr 32)
    }
}
