import Darwin
import Foundation

private let maxBody = 1 << 20
private func sendAll(_ fd: Int32, _ bytes: Data) {
    bytes.withUnsafeBytes { buffer in
        guard let base = buffer.baseAddress else { return }
        var offset = 0
        while offset < buffer.count {
            let written = send(fd, base.advanced(by: offset), buffer.count - offset, 0)
            if written < 0 && errno == EINTR { continue }
            if written <= 0 { return }
            offset += written
        }
    }
}
private func respond(_ fd: Int32, _ status: Int, _ body: Data = Data()) {
    let reason = [200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed", 413: "Payload Too Large"]
    let type = status == 200 ? "Content-Type: application/json\r\n" : ""
    let header = "HTTP/1.1 \(status) \(reason[status] ?? "Error")\r\n\(type)Connection: close\r\nContent-Length: \(body.count)\r\n\r\n"
    sendAll(fd, Data(header.utf8))
    sendAll(fd, body)
}

private func params(_ value: Any?) throws -> (UInt64, Options) {
    let invalid = RpcFailure(-32602, "Invalid params")
    guard let params = value as? [Any], (1...2).contains(params.count),
          let slot = (params[0] as? JSONNumber)?.unsigned else { throw invalid }
    let config: Object
    if params.count == 1 || params[1] is NSNull { config = [:] }
    else if let encoding = params[1] as? String { config = ["encoding": encoding] }
    else if let options = params[1] as? Object { config = options }
    else { throw invalid }
    func option(_ key: String) -> Any? {
        guard let value = config[key], !(value is NSNull) else { return nil }
        return value
    }
    func enumeration(_ key: String, _ values: [String]) throws -> String {
        guard let value = option(key) else { return values[0] }
        guard let text = value as? String, values.contains(text) else { throw invalid }
        return text
    }
    let encoding = try enumeration("encoding", ["json", "jsonParsed", "base64", "base58"])
    let details = try enumeration("transactionDetails", ["full", "accounts", "signatures", "none"])
    _ = try enumeration("commitment", ["finalized", "confirmed"])
    let rewards: Bool
    if let value = option("rewards") {
        guard let boolean = value as? Bool else { throw invalid }
        rewards = boolean
    } else { rewards = true }
    let maxVersion: UInt64?
    if let value = option("maxSupportedTransactionVersion") {
        guard let version = (value as? JSONNumber)?.unsigned, version <= 255 else { throw invalid }
        maxVersion = version
    } else { maxVersion = nil }
    if encoding == "base58" && (maxVersion ?? 0) >= 1 {
        throw RpcFailure(-32602, "base58 encoding is not supported with maxSupportedTransactionVersion >= 1")
    }
    if details == "accounts" && encoding != "json" { throw invalid }
    return (slot, Options(encoding: encoding, details: details, rewards: rewards, maxVersion: maxVersion))
}
private func error(_ id: Any, _ code: Int, _ message: String) -> Reply {
    Reply(object: ["error": ["code": code, "message": message] as Object], id: id)
}
private func dispatch(_ archive: Archive, _ value: Any) -> Reply {
    guard let request = value as? Object else { return error(null, -32600, "Invalid Request") }
    let proto = request["jsonrpc"] ?? null
    let method = request["method"] ?? null
    let id = request["id"] ?? null
    guard proto is String || proto is NSNull, method is String || method is NSNull,
          id is String || id is JSONNumber || id is NSNull else {
        return error(null, -32600, "Invalid Request")
    }
    guard proto as? String == "2.0", let method = method as? String else {
        return error(id, -32600, "Invalid Request")
    }
    do {
        let result: Any
        switch method {
        case "getHealth":
            let params = request["params"] ?? null
            guard params is NSNull || (params as? [Any])?.isEmpty == true else {
                throw RpcFailure(-32602, "Invalid params")
            }
            result = "ok"
        case "getBlock":
            let (slot, options) = try params(request["params"])
            result = try archive.block(slot, options)
        default: throw RpcFailure(-32601, "Method not found: \(method)")
        }
        return Reply(object: ["result": result], id: id)
    } catch let e as RpcFailure {
        return error(id, e.code, e.message)
    } catch {
        return Reply(object: ["error": ["code": -32603, "message": "Internal error"] as Object], id: id)
    }
}
private func encode(_ reply: Reply) -> Data {
    if let data = try? reply.encode() { return data }
    return (try? error(reply.id, -32603, "Internal error").encode()) ?? Data()
}
private func rpc(_ archive: Archive, _ bytes: [UInt8]) -> Data {
    guard let value = try? JSON(bytes).parse() else { return encode(error(null, -32700, "Parse error")) }
    if let batch = value as? [Any] {
        guard (1...100).contains(batch.count) else { return encode(error(null, -32600, "Invalid Request")) }
        var out = Data([91])
        for (i, value) in batch.enumerated() {
            if i != 0 { out.append(44) }
            out.append(encode(dispatch(archive, value)))
        }
        out.append(93)
        return out
    }
    return encode(dispatch(archive, value))
}
private func serve(_ fd: Int32, _ archive: Archive) {
    defer { close(fd) }
    var timeout = timeval(tv_sec: 10, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    let input = HTTPInput {
        var bytes = [UInt8](repeating: 0, count: 8192)
        let count = bytes.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
        guard count > 0 else { throw HTTPError(status: 400) }
        return Array(bytes[..<count])
    }
    do {
        let line = try input.line().split(separator: " ")
        guard line.count == 3, line[2] == "HTTP/1.1" || line[2] == "HTTP/1.0" else {
            throw HTTPError(status: 400)
        }
        let headers = try input.headers()
        guard line[1].split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first == "/" else {
            throw HTTPError(status: 404)
        }
        guard line[0] == "POST" else { throw HTTPError(status: 405) }
        respond(fd, 200, rpc(archive, try input.body(headers, maxBody)))
    } catch let error as HTTPError {
        respond(fd, error.status)
    } catch {
        respond(fd, 400)
    }
}
private func listener(_ host: String, _ port: String) throws -> Int32 {
    var hints = addrinfo()
    hints.ai_family = AF_UNSPEC
    hints.ai_socktype = SOCK_STREAM
    hints.ai_protocol = IPPROTO_TCP
    var addresses: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, port, &hints, &addresses) == 0, let addresses else { throw DecodeFailure() }
    defer { freeaddrinfo(addresses) }
    var next: UnsafeMutablePointer<addrinfo>? = addresses
    while let address = next {
        let info = address.pointee
        next = info.ai_next
        let fd = socket(info.ai_family, info.ai_socktype, info.ai_protocol)
        if fd < 0 { continue }
        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        if Darwin.bind(fd, info.ai_addr, info.ai_addrlen) == 0 && listen(fd, 128) == 0 { return fd }
        close(fd)
    }
    throw DecodeFailure()
}

private func main() throws {
    let env = ProcessInfo.processInfo.environment
    var bind = env["ONLYBLOCKS_BIND"] ?? "127.0.0.1:8899"
    var base = env["OLD_FAITHFUL_BASE_URL"] ?? "https://files.old-faithful.net"
    let args = Array(CommandLine.arguments.dropFirst())
    var i = 0
    while i < args.count {
        let fields = args[i].split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        i += 1
        guard let flag = fields.first, flag == "--bind" || flag == "--base-url" else { throw DecodeFailure() }
        let value: String
        if fields.count == 2 { value = String(fields[1]) }
        else {
            guard i < args.count else { throw DecodeFailure() }
            value = args[i]
            i += 1
        }
        if flag == "--bind" { bind = value } else { base = value }
    }
    base = base.trimmingCharacters(in: .whitespacesAndNewlines)
    while base.last == "/" { base.removeLast() }
    guard let url = URL(string: base), url.scheme == "http" || url.scheme == "https", url.host != nil,
          let colon = bind.lastIndex(of: ":") else { throw DecodeFailure() }
    var host = String(bind[..<colon])
    if host.first == "[" && host.last == "]" { host = String(host.dropFirst().dropLast()) }
    let port = String(bind[bind.index(after: colon)...])
    guard !host.isEmpty, UInt16(port) != nil else { throw DecodeFailure() }

    signal(SIGPIPE, SIG_IGN)
    let archive = Archive(base)
    let fd = try listener(host, port)
    let signals = [SIGINT, SIGTERM].map { sig -> DispatchSourceSignal in
        signal(sig, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: sig, queue: DispatchQueue(label: "shutdown"))
        source.setEventHandler { close(fd); exit(0) }
        source.resume()
        return source
    }
    let clients = DispatchSemaphore(value: 40)
    withExtendedLifetime(signals) {
        while true {
            clients.wait()
            let accepted = accept(fd, nil, nil)
            if accepted < 0 {
                clients.signal()
                if errno == EINTR { continue }
                break
            }
            DispatchQueue.global(qos: .userInitiated).async {
                serve(accepted, archive)
                clients.signal()
            }
        }
    }
}

do { try main() }
catch {
    FileHandle.standardError.write(Data("Invalid configuration or unable to bind\n".utf8))
    exit(1)
}
