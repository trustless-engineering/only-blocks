import Foundation

struct JSONNumber {
    let text: String
    var unsigned: UInt64? {
        text.utf8.allSatisfy { (48...57).contains($0) } ? UInt64(text) : nil
    }
}

/// Foundation decodes strings and writes results. The lexer retains number spellings
/// so that fractional/exponent slot literals are rejected and numeric IDs round-trip.
final class JSON {
    private let bytes: [UInt8]
    private var pos = 0
    init(_ bytes: [UInt8]) { self.bytes = bytes }
    private var next: UInt8? { pos < bytes.count ? bytes[pos] : nil }
    private func spaces() {
        while let byte = next, byte == 32 || byte == 9 || byte == 10 || byte == 13 { pos += 1 }
    }
    private func take(_ byte: UInt8) -> Bool {
        if next != byte { return false }
        pos += 1
        return true
    }
    func parse() throws -> Any {
        let value = try value(0)
        spaces()
        try check(pos == bytes.count)
        return value
    }
    private func literal(_ word: String, _ result: Any) throws -> Any {
        try check(bytes[pos...].starts(with: word.utf8))
        pos += word.utf8.count
        return result
    }
    private func value(_ depth: Int) throws -> Any {
        try check(depth <= 128)
        spaces()
        switch next {
        case 123:
            pos += 1
            spaces()
            var object = Object()
            if !take(125) {
                repeat {
                    spaces()
                    let name = try string()
                    spaces()
                    try check(take(58))
                    object[name] = try value(depth + 1)
                    spaces()
                } while take(44)
                try check(take(125))
            }
            return object
        case 91:
            pos += 1
            spaces()
            var list = [Any]()
            if !take(93) {
                repeat {
                    list.append(try value(depth + 1))
                    spaces()
                } while take(44)
                try check(take(93))
            }
            return list
        case 34: return try string()
        case 110: return try literal("null", null)
        case 116: return try literal("true", true)
        case 102: return try literal("false", false)
        default: return try number()
        }
    }
    private func string() throws -> String {
        let start = pos
        try check(take(34))
        while let byte = next {
            pos += 1
            if byte == 34 {
                let fragment = Data(bytes[start..<pos])
                guard let text = try JSONSerialization.jsonObject(with: fragment, options: .fragmentsAllowed) as? String
                else { throw DecodeFailure() }
                return text
            }
            try check(byte >= 32)
            if byte == 92 {
                try check(next != nil)
                pos += 1
            }
        }
        throw DecodeFailure()
    }
    private func digits() throws {
        let start = pos
        while let n = next, (48...57).contains(n) { pos += 1 }
        try check(pos > start)
    }
    private func number() throws -> JSONNumber {
        let start = pos
        _ = take(45)
        if !take(48) { try digits() }
        if take(46) { try digits() }
        if take(101) || take(69) {
            if !take(43) { _ = take(45) }
            try digits()
        }
        return JSONNumber(text: String(decoding: bytes[start..<pos], as: UTF8.self))
    }
}
struct Reply {
    var object: Object
    let id: Any
    func encode() throws -> Data {
        var object = self.object
        object["jsonrpc"] = "2.0"
        if let number = id as? JSONNumber {
            var data = try JSONSerialization.data(withJSONObject: object)
            data.removeLast()
            data.append(contentsOf: (",\"id\":" + number.text + "}").utf8)
            return data
        }
        object["id"] = id
        return try JSONSerialization.data(withJSONObject: object)
    }
}
