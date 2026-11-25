import Foundation

struct DecodeFailure: Error {}
@inline(__always) func check(_ condition: Bool) throws {
    if !condition { throw DecodeFailure() }
}
typealias Object = [String: Any]
let null = NSNull()

final class Bytes {
    let data: [UInt8]
    var pos: Int
    let end: Int
    init(_ data: [UInt8], _ start: Int = 0, _ end: Int? = nil) {
        self.data = data
        self.pos = start
        self.end = end ?? data.count
    }
    var left: Int { end - pos }
    func skip(_ n: Int) throws {
        try check(n >= 0 && n <= left)
        pos += n
    }
    func u8() throws -> Int {
        try skip(1)
        return Int(data[pos - 1])
    }
    func le(_ n: Int) throws -> UInt64 {
        var value: UInt64 = 0
        for i in 0..<n { value |= UInt64(try u8()) << (8 * i) }
        return value
    }
    func u32() throws -> Int { Int(try le(4)) }
    func u64() throws -> UInt64 { try le(8) }
    func varint() throws -> UInt64 {
        var value: UInt64 = 0
        for i in 0..<10 {
            let byte = try u8()
            try check(i < 9 || byte <= 1)
            value |= UInt64(byte & 127) << (7 * i)
            if byte < 128 { return value }
        }
        throw DecodeFailure()
    }
    func short() throws -> Int {
        var value = 0
        for i in 0..<3 {
            let b = try u8()
            try check((i == 0 || b != 0) && (i < 2 || b < 4))
            value |= (b & 127) << (7 * i)
            if b < 128 { return value }
        }
        throw DecodeFailure()
    }
    func count(_ value: UInt64, _ limit: Int? = nil) throws -> Int {
        try check(value <= UInt64(limit ?? left))
        return Int(value)
    }
    func bytes(_ n: Int) throws -> [UInt8] {
        let start = pos
        try skip(n)
        return Array(data[start..<pos])
    }
    func part(_ n: Int) throws -> Bytes {
        let start = pos
        try skip(n)
        return Bytes(data, start, pos)
    }
    func vector() throws -> [UInt8] { try bytes(count(u64())) }
    func text() throws -> String { try utf8(vector()) }
    func list<T>(_ read: () throws -> T) throws -> [T] {
        try items(count(u64()), read)
    }
    func option<T>(_ read: () throws -> T) throws -> T? {
        if left == 0 { return nil }
        switch try u8() {
        case 0: return nil
        case 1: return try read()
        default: throw DecodeFailure()
        }
    }
}

func items<T>(_ count: Int, _ read: () throws -> T) rethrows -> [T] {
    var out = [T]()
    out.reserveCapacity(min(count, 1024))
    for _ in 0..<count { out.append(try read()) }
    return out
}
func utf8(_ bytes: [UInt8]) throws -> String {
    guard let text = String(bytes: bytes, encoding: .utf8) else { throw DecodeFailure() }
    return text
}
extension Array where Element == UInt8 {
    var b64: String { Data(self).base64EncodedString() }
    var b58: String {
        let alphabet = Array<UInt8>("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
        let zeros = prefix(while: { $0 == 0 }).count
        var digits = [UInt8]()
        for byte in self.dropFirst(zeros) {
            var carry = Int(byte)
            for i in digits.indices {
                carry += Int(digits[i]) * 256
                digits[i] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }
        return String(decoding: Swift.Array<UInt8>(repeating: 49, count: zeros) +
            digits.reversed().map { alphabet[Int($0)] }, as: UTF8.self)
    }
    func pubkey() throws -> String {
        try check(count == 32)
        return b58
    }
}

indirect enum Cbor {
    case unsigned(UInt64), signed(Int64), bytes([UInt8]), text(String), array([Cbor]), map([String: Cbor]), ignored
    var bytes: [UInt8]? { if case .bytes(let bytes) = self { return bytes }; return nil }
    var array: [Cbor]? { if case .array(let fields) = self { return fields }; return nil }
    var u64: UInt64? { if case .unsigned(let n) = self { return n }; return nil }
    var i64: Int64? {
        if case .signed(let n) = self { return n }
        if let n = u64 { return Int64(exactly: n) }
        return nil
    }
    func node(_ kind: UInt64) throws -> [Cbor] {
        guard let fields = array, fields.first?.u64 == kind else { throw DecodeFailure() }
        return fields
    }
}
extension Array where Element == Cbor {
    subscript(optional i: Int) -> Cbor { i < count ? self[i] : .ignored }
}
func cbor(_ r: Bytes, _ depth: Int = 0) throws -> Cbor {
    try check(depth <= 128)
    let header = try r.u8()
    let major = header >> 5, info = header & 31
    if major == 7 {
        switch info {
        case 20...23: break
        case 25...27: try r.skip(1 << (info - 24))
        default: throw DecodeFailure()
        }
        return .ignored
    }
    var arg = UInt64(info)
    if (24...27).contains(info) {
        arg = 0
        for _ in 0..<(1 << (info - 24)) { arg = (arg << 8) | UInt64(try r.u8()) }
    }
    let indefinite = info == 31
    try check(info < 28 || indefinite && (2...5).contains(major))
    func values(_ read: () throws -> Void) throws {
        if indefinite {
            while r.left > 0 && r.data[r.pos] != 255 { try read() }
            try r.skip(1)
        } else {
            for _ in 0..<(try r.count(arg)) { try read() }
        }
    }
    switch major {
    case 0: return .unsigned(arg)
    case 1:
        guard let n = Int64(exactly: arg) else { return .ignored }
        return .signed(-1 - n)
    case 2, 3:
        var bytes = [UInt8]()
        if indefinite {
            try values {
                let b = Int(r.data[r.pos])
                try check(b >> 5 == major && b & 31 != 31)
                let part = try cbor(r, depth + 1)
                switch part {
                case .bytes(let chunk): bytes += chunk
                case .text(let text): bytes += text.utf8
                default: throw DecodeFailure()
                }
            }
        } else { bytes = try r.bytes(r.count(arg)) }
        return major == 2 ? .bytes(bytes) : .text(try utf8(bytes))
    case 4:
        var fields = [Cbor]()
        try values { fields.append(try cbor(r, depth + 1)) }
        return .array(fields)
    case 5:
        var fields = [String: Cbor]()
        try values {
            let key = try cbor(r, depth + 1)
            let value = try cbor(r, depth + 1)
            if case .text(let text) = key { fields[text] = value }
        }
        return .map(fields)
    case 6: return try cbor(r, depth + 1)
    default: throw DecodeFailure()
    }
}
struct CID {
    let key: Data
    let absent: Bool
    init(_ r: Bytes) throws {
        let start = r.pos
        let a = try r.varint(), b = try r.varint()
        var empty = false
        if a == 18 && b == 32 { try r.skip(32) }
        else {
            try check(a == 1)
            let code = try r.varint(), count = try r.count(r.varint(), 64)
            try r.skip(count)
            empty = code == 0 && count == 0
        }
        key = Data(r.data[start..<r.pos])
        absent = empty
    }
    init(link: Cbor) throws {
        guard let bytes = link.bytes else { throw DecodeFailure() }
        let r = Bytes(bytes)
        let prefix = try r.u8()
        try check(prefix == 0)
        try self.init(r)
    }
}
func links(_ field: Cbor) throws -> [CID] { try (field.array ?? []).map(CID.init(link:)) }

struct Car {
    private let bytes: [UInt8]
    private let index: [Data: Range<Int>]
    let block: [Cbor]
    init(_ bytes: [UInt8]) throws {
        var index: [Data: Range<Int>] = [:]
        var block: Range<Int>?
        var first = true
        let r = Bytes(bytes)
        while r.left > 0 {
            let n = try r.count(r.varint(), 32 << 20)
            if n == 0 { continue }
            let part = try r.part(n)
            let start = part.pos
            let header = first && bytes[start] & 0xe0 == 0xa0 &&
                Self.isHeader(bytes, start..<part.end)
            first = false
            if header { continue }
            let cid = try CID(part)
            let range = part.pos..<part.end
            index[cid.key] = range
            if range.count <= 1 { continue }
            let tag = Int(bytes[part.pos]), info = tag & 31
            let extra = info < 24 || info == 31 ? 0 : info <= 27 ? 1 << (info - 24) : -1
            if tag >> 5 == 4 && extra >= 0 && range.count > 1 + extra && bytes[part.pos + 1 + extra] == 2 {
                block = range
            }
        }
        guard let block else { throw DecodeFailure() }
        self.block = try Self.decode(bytes, block).node(2)
        try check(self.block[optional: 1].u64 != nil)
        self.index = index
        self.bytes = bytes
    }
    private static func decode(_ bytes: [UInt8], _ range: Range<Int>) throws -> Cbor {
        let r = Bytes(bytes, range.lowerBound, range.upperBound)
        let value = try cbor(r)
        try check(r.left == 0)
        return value
    }
    private static func isHeader(_ bytes: [UInt8], _ range: Range<Int>) -> Bool {
        if case .map(let fields) = try? decode(bytes, range) { return fields["version"] != nil }
        return false
    }
    func find(_ cid: CID, _ kind: UInt64) throws -> [Cbor]? {
        guard let range = index[cid.key] else { return nil }
        return try Self.decode(bytes, range).node(kind)
    }
    func get(_ cid: CID, _ kind: UInt64) throws -> [Cbor] {
        guard let result = try find(cid, kind) else { throw DecodeFailure() }
        return result
    }
    func payload(_ root: Cbor) throws -> [UInt8] {
        let fields = try root.node(6)
        var bytes = fields[optional: 4].bytes ?? []
        var stack = Array(try links(fields[optional: 5]).reversed())
        var seen = Set<Data>()
        while let cid = stack.popLast() {
            try check(seen.insert(cid.key).inserted)
            let child = try get(cid, 6)
            bytes += child[optional: 4].bytes ?? []
            stack += try links(child[optional: 5]).reversed()
        }
        if let hash = fields[optional: 1].u64 { try check(crc64(bytes) == hash || fnv(bytes) == hash) }
        return bytes
    }
}

private let crcTable = (0..<256).map { byte -> UInt64 in
    var v = UInt64(byte)
    for _ in 0..<8 { v = (v >> 1) ^ (v & 1 == 0 ? 0 : 0xd800000000000000) }
    return v
}
private func crc64(_ bytes: [UInt8]) -> UInt64 {
    var crc = UInt64.max
    for b in bytes { crc = (crc >> 8) ^ crcTable[Int(UInt8(truncatingIfNeeded: crc) ^ b)] }
    return ~crc
}
private func fnv(_ bytes: [UInt8]) -> UInt64 {
    bytes.reduce(0xcbf29ce484222325) { ($0 ^ UInt64($1)) &* 0x100000001b3 }
}
