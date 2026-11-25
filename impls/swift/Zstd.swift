enum Zstd {
    private static let maxOutput = 512 << 20
    private static let maxBlock = 128 << 10
    private static let LL_BASE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
           16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
           8192, 16384, 32768, 65536]
    private static let LL_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
           13, 14, 15, 16]
    private static let ML_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
           19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
           35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
           4099, 8195, 16387, 32771, 65539]
    private static let ML_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
           1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
           12, 13, 14, 15, 16]
    private static let LL_DEFAULT = [4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
              2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
              -1, -1, -1, -1]
    private static let ML_DEFAULT = [1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
              -1, -1, -1, -1, -1]
    private static let OF_DEFAULT = [1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
              1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1]

    private static func high(_ value: Int) -> Int { Int.bitWidth - 1 - value.leadingZeroBitCount }
    private struct Backward {
        let r: Bytes
        var bits: Int
        init(_ r: Bytes) throws {
            try check(r.left > 0 && r.data[r.end - 1] != 0)
            self.r = r
            bits = 8 * (r.left - 1) + high(Int(r.data[r.end - 1]))
        }
        func peek(_ n: Int) -> Int {
            if n == 0 || bits <= 0 { return 0 }
            let low = bits - n
            let from = max(0, low), first = from >> 3, last = (bits - 1) >> 3
            var word = 0
            for i in first...last { word |= Int(r.data[r.pos + i]) << (8 * (i - first)) }
            let mask = (1 << (bits - from)) - 1
            return ((word >> (from & 7)) & mask) << (from - low)
        }
        mutating func read(_ n: Int) -> Int {
            let value = peek(n)
            bits -= n
            return value
        }
    }
    private struct Cell {
        let symbol: Int
        let bits: Int
        let base: Int
    }
    private struct Table {
        let cells: [Cell]
        let log: Int
    }
    private static func fse(_ prob: [Int], _ log: Int) throws -> Table {
        let size = 1 << log
        try check(prob.reduce(0) { $0 + abs($1) } == size)
        var symbols = [Int](repeating: 0, count: size), counts = prob
        var top = size - 1
        for i in prob.indices where prob[i] == -1 {
            symbols[top] = i
            top -= 1
            counts[i] = 1
        }
        let step = (size >> 1) + (size >> 3) + 3
        var pos = 0
        for i in prob.indices where prob[i] > 0 {
            for _ in 0..<prob[i] {
                symbols[pos] = i
                repeat { pos = (pos + step) & (size - 1) } while pos > top
            }
        }
        try check(pos == 0)
        let cells = symbols.map { symbol -> Cell in
            let n = counts[symbol]
            counts[symbol] += 1
            let bits = log - high(n)
            return Cell(symbol: symbol, bits: bits, base: (n << bits) - size)
        }
        return Table(cells: cells, log: log)
    }
    private static func readFse(_ r: Bytes, _ maxSymbol: Int, _ maxLog: Int) throws -> Table {
        var cursor = 8 * r.pos
        func peek(_ n: Int) -> Int {
            var v = 0
            for i in 0..<n {
                let p = cursor + i
                if p >> 3 < r.end { v |= Int((r.data[p >> 3] >> (p & 7)) & 1) << i }
            }
            return v
        }
        func read(_ n: Int) throws -> Int {
            let value = peek(n)
            cursor += n
            try check(cursor <= 8 * r.end)
            return value
        }
        let log = try read(4) + 5
        try check(log <= maxLog)
        var threshold = 1 << log, width = log + 1
        var remaining = threshold + 1
        var prob = [Int]()
        while remaining > 1 {
            try check(prob.count <= maxSymbol)
            let largest = 2 * threshold - 1 - remaining
            let low = peek(width - 1)
            var value: Int
            if low < largest { value = try read(width - 1) }
            else {
                value = try read(width)
                if value >= threshold { value -= largest }
            }
            let p = value - 1
            prob.append(p)
            remaining -= abs(p)
            try check(remaining >= 1)
            if p == 0 {
                var count: Int
                repeat {
                    count = try read(2)
                    prob += repeatElement(0, count: count)
                    try check(prob.count <= maxSymbol + 1)
                } while count == 3
            }
            while remaining < threshold {
                width -= 1
                threshold >>= 1
            }
        }
        r.pos = (cursor + 7) >> 3
        return try fse(prob, log)
    }

    private static func huffman(_ r: Bytes) throws -> Table {
        let header = try r.u8()
        var weights = [Int]()
        if header >= 128 {
            let count = header - 127
            let packed = try r.bytes((count + 1) / 2)
            for i in 0..<count {
                weights.append(Int((packed[i / 2] >> (i % 2 == 0 ? 4 : 0)) & 15))
            }
        } else {
            let part = try r.part(header)
            let table = try readFse(part, 255, 6)
            var br = try Backward(part)
            var states = [br.read(table.log), br.read(table.log)]
            try check(br.bits >= 0)
            var i = 0
            while true {
                try check(weights.count < 255)
                let cell = table.cells[states[i]]
                weights.append(cell.symbol)
                states[i] = cell.base + br.read(cell.bits)
                i ^= 1
                if br.bits < 0 {
                    weights.append(table.cells[states[i]].symbol)
                    break
                }
            }
        }
        try check(weights.count <= 255 && weights.allSatisfy { $0 <= 11 })
        let total = weights.reduce(0) { $0 + ($1 == 0 ? 0 : 1 << ($1 - 1)) }
        try check(total > 0)
        let log = high(total) + 1, rest = (1 << log) - total
        try check(log <= 11 && rest.nonzeroBitCount == 1)
        weights.append(high(rest) + 1)
        var cells = [Cell]()
        for w in 1...log {
            for (s, weight) in weights.enumerated() where weight == w {
                cells += repeatElement(Cell(symbol: s, bits: log + 1 - w, base: 0), count: 1 << (w - 1))
            }
        }
        return Table(cells: cells, log: log)
    }

    private final class Frame {
        let start: Int
        let window: Int
        var rep = [1, 4, 8]
        var tables = [Table?](repeating: nil, count: 3)
        var huffman: Table?
        init(_ start: Int, _ window: Int) { self.start = start; self.window = window }
        func offset(_ value: Int, _ literals: Int) -> Int {
            let index = value > 3 ? 3 : value - 1 + (literals == 0 ? 1 : 0)
            let offset = value > 3 ? value - 3 : index == 3 ? rep[0] - 1 : rep[index]
            if index != 0 {
                if index >= 2 { rep[2] = rep[1] }
                rep[1] = rep[0]
                rep[0] = offset
            }
            return offset
        }
    }
    private static func literals(_ r: Bytes, _ frame: Frame) throws -> [UInt8] {
        let first = try r.u8(), type = first & 3, format = (first >> 2) & 3
        if type < 2 {
            let n: Int
            switch format {
            case 0, 2: n = first >> 3
            case 1: n = (first >> 4) + (try r.u8() << 4)
            default: n = (first >> 4) + (Int(try r.le(2)) << 4)
            }
            try check(n <= maxBlock)
            if type == 0 { return try r.bytes(n) }
            return [UInt8](repeating: UInt8(try r.u8()), count: n)
        }
        let width = format < 2 ? 10 : format == 2 ? 14 : 18
        let header = first | (Int(try r.le((width - 10) / 4 + 2)) << 8)
        let n = (header >> 4) & ((1 << width) - 1)
        try check(n <= maxBlock)
        let part = try r.part(header >> (4 + width))
        if type == 2 { frame.huffman = try huffman(part) }
        guard let table = frame.huffman else { throw DecodeFailure() }
        var out = [UInt8]()
        out.reserveCapacity(n)
        func stream(_ input: Bytes, _ count: Int) throws {
            var br = try Backward(input)
            for _ in 0..<count {
                let cell = table.cells[br.peek(table.log)]
                br.bits -= cell.bits
                try check(br.bits >= 0)
                out.append(UInt8(cell.symbol))
            }
            try check(br.bits == 0)
        }
        if format == 0 { try stream(part, n) }
        else {
            let sizes = try items(3) { Int(try part.le(2)) }
            let quarter = (n + 3) / 4
            try check(n >= 3 * quarter)
            for size in sizes { try stream(part.part(size), quarter) }
            try stream(part, n - 3 * quarter)
        }
        return out
    }
    private static let predefined = [try! fse(LL_DEFAULT, 6), try! fse(OF_DEFAULT, 5), try! fse(ML_DEFAULT, 6)]
    private static let maxSymbols = [35, 31, 52], maxLogs = [9, 8, 9]
    private static func compressed(_ r: Bytes, _ out: inout [UInt8], _ frame: Frame, _ limit: Int) throws {
        let literals = try literals(r, frame), start = out.count, first = try r.u8()
        if first == 0 {
            try check(r.left == 0 && literals.count <= limit && literals.count <= maxOutput - out.count)
            out += literals
            return
        }
        let count: Int
        if first < 128 { count = first }
        else if first < 255 { count = ((first - 128) << 8) + (try r.u8()) }
        else { count = Int(try r.le(2)) + 0x7f00 }
        let modes = try r.u8()
        try check(modes & 3 == 0)
        let tables = try (0..<3).map { i -> Table in
            let table: Table
            switch (modes >> (6 - 2 * i)) & 3 {
            case 0: table = predefined[i]
            case 1:
                let code = try r.u8()
                try check(code <= maxSymbols[i])
                table = Table(cells: [Cell(symbol: code, bits: 0, base: 0)], log: 0)
            case 2: table = try readFse(r, maxSymbols[i], maxLogs[i])
            default:
                guard let previous = frame.tables[i] else { throw DecodeFailure() }
                table = previous
            }
            frame.tables[i] = table
            return table
        }
        var br = try Backward(r)
        var ll = br.read(tables[0].log), of = br.read(tables[1].log), ml = br.read(tables[2].log)
        var lit = 0
        for i in 0..<count {
            let lc = tables[0].cells[ll], oc = tables[1].cells[of], mc = tables[2].cells[ml]
            let value = (1 << oc.symbol) + br.read(oc.symbol)
            let matches = ML_BASE[mc.symbol] + br.read(ML_BITS[mc.symbol])
            let length = LL_BASE[lc.symbol] + br.read(LL_BITS[lc.symbol])
            try check(br.bits >= 0 && lit + length <= literals.count &&
                out.count - start + length + matches <= limit && length + matches <= maxOutput - out.count)
            out += literals[lit..<lit + length]
            lit += length
            let offset = frame.offset(value, length)
            try check(offset > 0 && offset <= frame.window && offset <= out.count - frame.start)
            for _ in 0..<matches {
                let byte = out[out.count - offset]
                out.append(byte)
            }
            if i + 1 < count {
                ll = lc.base + br.read(lc.bits)
                ml = mc.base + br.read(mc.bits)
                of = oc.base + br.read(oc.bits)
                try check(br.bits >= 0)
            }
        }
        let trailing = literals.count - lit
        try check(br.bits == 0 && out.count - start + trailing <= limit && trailing <= maxOutput - out.count)
        out += literals[lit...]
    }

    static func decode(_ bytes: [UInt8]) throws -> [UInt8] {
        let r = Bytes(bytes)
        var out = [UInt8]()
        while r.left > 0 {
            let magic = try r.u32()
            if magic & 0xfffffff0 == 0x184d2a50 {
                try r.skip(r.count(r.le(4)))
                continue
            }
            try check(magic == 0xfd2fb528)
            let descriptor = try r.u8(), single = descriptor & 32 != 0
            try check(descriptor & 8 == 0)
            var window = 0
            if !single {
                let wd = try r.u8(), base = 1 << (10 + (wd >> 3))
                window = base + (base >> 3) * (wd & 7)
            }
            let did = try r.le([0, 1, 2, 4][descriptor & 3])
            try check(did == 0)
            let width = [single ? 1 : 0, 2, 4, 8][descriptor >> 6]
            let size = try r.le(width) + (width == 2 ? 256 : 0)
            try check(size <= UInt64(maxOutput - out.count))
            let frame = Frame(out.count, single ? Int(size) : window)
            let limit = min(maxBlock, frame.window)
            var header: Int
            repeat {
                header = Int(try r.le(3))
                let n = header >> 3
                try check(n <= limit)
                switch (header >> 1) & 3 {
                case 0:
                    try check(n <= maxOutput - out.count)
                    let part = try r.part(n)
                    out += part.data[part.pos..<part.end]
                case 1:
                    try check(n <= maxOutput - out.count)
                    out += repeatElement(UInt8(try r.u8()), count: n)
                case 2: try compressed(r.part(n), &out, frame, limit)
                default: throw DecodeFailure()
                }
            } while header & 1 == 0
            try check(width == 0 || Int(size) == out.count - frame.start)
            if descriptor & 4 != 0 {
                let expected = try r.u32()
                let checksum = try xxh64(out, frame.start)
                try check(expected == Int(UInt32(truncatingIfNeeded: checksum)))
            }
        }
        return out
    }

    private static let p1: UInt64 = 0x9e3779b185ebca87, p2: UInt64 = 0xc2b2ae3d27d4eb4f,
        p3: UInt64 = 0x165667b19e3779f9, p4: UInt64 = 0x85ebca77c2b2ae63, p5: UInt64 = 0x27d4eb2f165667c5
    private static func rot(_ x: UInt64, _ n: Int) -> UInt64 { (x << n) | (x >> (64 - n)) }
    private static func round(_ a: UInt64, _ lane: UInt64) -> UInt64 {
        rot(a &+ lane &* p2, 31) &* p1
    }
    private static func xxh64(_ bytes: [UInt8], _ start: Int) throws -> UInt64 {
        let r = Bytes(bytes, start)
        var h = p5
        if r.left >= 32 {
            var lanes = [p1 &+ p2, p2, 0, 0 &- p1]
            while r.left >= 32 {
                for i in lanes.indices { lanes[i] = round(lanes[i], try r.u64()) }
            }
            h = rot(lanes[0], 1) &+ rot(lanes[1], 7) &+ rot(lanes[2], 12) &+ rot(lanes[3], 18)
            for lane in lanes { h = (h ^ round(0, lane)) &* p1 &+ p4 }
        }
        h = h &+ UInt64(bytes.count - start)
        while r.left >= 8 { h = rot(h ^ round(0, try r.u64()), 27) &* p1 &+ p4 }
        if r.left >= 4 { h = rot(h ^ ((try r.le(4)) &* p1), 23) &* p2 &+ p3 }
        while r.left > 0 { h = rot(h ^ (UInt64(try r.u8()) &* p5), 11) &* p1 }
        h = (h ^ (h >> 33)) &* p2
        h = (h ^ (h >> 29)) &* p3
        return h ^ (h >> 32)
    }
}
