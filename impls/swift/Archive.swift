import Foundation

struct RpcFailure: Error {
    let code: Int
    let message: String
    init(_ code: Int, _ message: String) { self.code = code; self.message = message }
}

private final class Lru<Value> {
    private final class Node {
        let key: UInt64
        var value: Value
        weak var previous: Node?
        var next: Node?
        init(_ key: UInt64, _ value: Value) { self.key = key; self.value = value }
    }
    private var entries: [UInt64: Node] = [:]
    private var first: Node?
    private var last: Node?
    private let lock = NSLock()

    private func unlink(_ node: Node) {
        if let previous = node.previous { previous.next = node.next }
        else { first = node.next }
        if let next = node.next { next.previous = node.previous }
        else { last = node.previous }
    }
    private func append(_ node: Node) {
        node.previous = last
        node.next = nil
        last?.next = node
        last = node
        if first == nil { first = node }
    }
    func get(_ key: UInt64) -> Value? {
        lock.lock()
        defer { lock.unlock() }
        guard let node = entries[key] else { return nil }
        unlink(node)
        append(node)
        return node.value
    }
    func put(_ key: UInt64, _ value: Value) {
        lock.lock()
        defer { lock.unlock() }
        if let node = entries[key] {
            node.value = value
            unlink(node)
            append(node)
        } else {
            let node = Node(key, value)
            entries[key] = node
            append(node)
            if entries.count > 100_000, let first {
                unlink(first)
                entries.removeValue(forKey: first.key)
            }
        }
    }
}

private let zeroHash = String(repeating: "1", count: 32)
let maxSlice = 128 << 20
final class Archive: @unchecked Sendable {
    private struct Range { let offset: UInt64; let length: Int }
    private let base: String
    private let client = HTTPClient()
    private let ranges = Lru<Range>()
    private let hashes = Lru<String>()
    private let permits = DispatchSemaphore(value: 32)
    init(_ base: String) { self.base = base }

    private func retryDelay(_ header: String?, _ failures: Int) -> TimeInterval {
        if let text = header?.trimmingCharacters(in: .whitespaces) {
            if let seconds = UInt64(text) { return Double(min(seconds, 10)) }
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
            if let date = formatter.date(from: text) { return max(0, min(10, date.timeIntervalSinceNow)) }
        }
        let base = 0.2 * Double(1 << failures)
        return .random(in: base / 2...base)
    }

    private func read(_ slot: UInt64, _ suffix: String, _ start: UInt64, _ length: Int, _ cap: Int) throws -> [UInt8] {
        let (end, overflow) = start.addingReportingOverflow(UInt64(length - 1))
        try check(!overflow)
        let epoch = slot / 432_000
        guard let url = URL(string: "\(base)/\(epoch)/epoch-\(epoch)\(suffix)") else { throw DecodeFailure() }
        let range = "bytes=\(start)-\(end)"
        func attempt() throws -> RangeResponse? {
            permits.wait()
            defer { permits.signal() }
            do { return try client.range(url, range, cap) }
            catch let error as DecodeFailure { throw error }
            catch { return nil }
        }
        for failures in 0..<5 {
            let response = try attempt()
            switch response?.status {
            case 206:
                guard let body = response?.body, body.count == length else { throw DecodeFailure() }
                return body
            case 404: throw RpcFailure(-32004, "Block not available for slot \(slot)")
            case 429, nil: break
            case let status? where (500...599).contains(status): break
            default: throw DecodeFailure()
            }
            if failures < 4 { Thread.sleep(forTimeInterval: retryDelay(response?.retryAfter, failures)) }
        }
        throw DecodeFailure()
    }
    private func load(_ slot: UInt64) throws -> Car {
        let range: Range
        if let existing = ranges.get(slot) { range = existing }
        else {
            let r = Bytes(try read(slot, "-slot-ranges.raw", (slot % 432_000) * 12, 12, 12))
            range = try Range(offset: r.u64(), length: r.u32())
            ranges.put(slot, range)
        }
        if range.length == 0 { throw RpcFailure(-32007, "Slot \(slot) was skipped") }
        try check(range.length <= maxSlice)
        return try Car(read(slot, ".car", range.offset, range.length, maxSlice))
    }
    private func hash(_ slot: UInt64, _ car: Car, _ links: [CID]) throws -> String {
        let hash: String
        if let cid = links.last {
            guard let bytes = try car.get(cid, 1)[optional: 2].bytes else { throw DecodeFailure() }
            hash = try bytes.pubkey()
        } else { hash = zeroHash }
        hashes.put(slot, hash)
        return hash
    }
    func block(_ slot: UInt64, _ options: Options) throws -> Object {
        let car = try load(slot), block = car.block
        try check(block[optional: 1].u64 == slot)
        let entries = try links(block[optional: 3])
        let info = block[optional: 4].array ?? []
        let parent = info[optional: 0].u64 ?? 0
        let current = try hash(slot, car, entries)
        let previous: String
        if slot == 0 { previous = zeroHash }
        else if let cached = hashes.get(parent) { previous = cached }
        else {
            let p = try load(parent)
            previous = try hash(parent, p, links(p.block[optional: 3]))
        }
        let timestamp = info[optional: 1].i64.flatMap { $0 == 0 ? nil : Optional($0) }
        var result: Object = ["blockhash": current, "previousBlockhash": previous, "parentSlot": parent,
            "blockTime": nullable(timestamp), "blockHeight": nullable(info[optional: 2].u64)]
        if options.details != "none" {
            let onlySignatures = options.details == "signatures"
            var out = [Any]()
            for cid in entries {
                let entry = try car.get(cid, 1)
                try check(entry[optional: 2].bytes?.count == 32)
                for link in try links(entry[optional: 3]) {
                    let node = try car.get(link, 0)
                    let tx = try Transaction(car.payload(node[optional: 1]))
                    if onlySignatures {
                        guard let signature = tx.signatures.first else { throw DecodeFailure() }
                        out.append(signature.b58)
                    } else {
                        let meta = node[optional: 2]
                        let decoded = try meta.array == nil ? nil : metadata(slot, car.payload(meta))
                        out.append(try tx.json(decoded, options))
                    }
                }
            }
            result[onlySignatures ? "signatures" : "transactions"] = out
        }
        if options.rewards {
            let field = block[optional: 5]
            var data = [UInt8]()
            if field.bytes != nil {
                let cid = try CID(link: field)
                if !cid.absent, let node = try car.find(cid, 5), node.count > 2 { data = try car.payload(node[2]) }
            }
            for (key, value) in try rewards(slot, data) { result[key] = value }
        }
        return result
    }
}
