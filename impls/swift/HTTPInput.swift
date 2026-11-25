import Foundation

struct HTTPError: Error { let status: Int }

final class HTTPInput {
    private let receive: () throws -> [UInt8]
    private var pending = [UInt8]()
    private var cursor = 0
    init(_ receive: @escaping () throws -> [UInt8]) { self.receive = receive }
    private func fill() throws {
        pending = try receive()
        guard !pending.isEmpty else { throw HTTPError(status: 400) }
        cursor = 0
    }
    func untilEOF(_ cap: Int) throws -> [UInt8] {
        var body = Array(pending[cursor...])
        if body.count > cap { throw HTTPError(status: 413) }
        while true {
            let chunk = try receive()
            if chunk.isEmpty { return body }
            if chunk.count > cap - body.count { throw HTTPError(status: 413) }
            body += chunk
        }
    }
    func line() throws -> String {
        var bytes = [UInt8]()
        while bytes.count < 8192 {
            if cursor == pending.count { try fill() }
            let byte = pending[cursor]
            cursor += 1
            if byte == 10 {
                guard bytes.last == 13 else { throw HTTPError(status: 400) }
                return String(decoding: bytes.dropLast(), as: UTF8.self)
            }
            bytes.append(byte)
        }
        throw HTTPError(status: 400)
    }
    func read(_ n: Int) throws -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(n)
        while out.count < n {
            if cursor == pending.count { try fill() }
            let size = min(n - out.count, pending.count - cursor)
            out += pending[cursor..<cursor + size]
            cursor += size
        }
        return out
    }
    func headers() throws -> [String: String] {
        var out = [String: String]()
        var total = 0
        while true {
            let line = try line()
            total += line.utf8.count + 2
            if total > 32 << 10 { throw HTTPError(status: 400) }
            if line.isEmpty { return out }
            let fields = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard fields.count == 2, !fields[0].isEmpty else { throw HTTPError(status: 400) }
            let name = fields[0].lowercased()
            if out[name] != nil && (name == "content-length" || name == "transfer-encoding") {
                throw HTTPError(status: 400)
            }
            out[name] = fields[1].trimmingCharacters(in: .whitespaces)
        }
    }
    func body(_ headers: [String: String], _ cap: Int, closeDelimited: Bool = false) throws -> [UInt8] {
        if let encoding = headers["transfer-encoding"] {
            guard encoding.lowercased() == "chunked", headers["content-length"] == nil else {
                throw HTTPError(status: 400)
            }
            var body = [UInt8]()
            while true {
                let header = try line()
                let length = header.prefix(while: { $0 != ";" })
                guard !length.isEmpty, length.utf8.allSatisfy({
                    (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0)
                }) else { throw HTTPError(status: 400) }
                guard let n = UInt64(length, radix: 16), n <= UInt64(cap - body.count) else {
                    throw HTTPError(status: 413)
                }
                if n == 0 { _ = try self.headers(); return body }
                body += try read(Int(n))
                let end = try read(2)
                guard end == [13, 10] else { throw HTTPError(status: 400) }
            }
        }
        guard let header = headers["content-length"] else { return closeDelimited ? try untilEOF(cap) : [] }
        guard !header.isEmpty, header.utf8.allSatisfy({ (48...57).contains($0) }) else {
            throw HTTPError(status: 400)
        }
        guard let length = UInt64(header), length <= UInt64(cap) else { throw HTTPError(status: 413) }
        return try read(Int(length))
    }
}
