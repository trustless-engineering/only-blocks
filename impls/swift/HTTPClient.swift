import Foundation
import Network

struct RangeResponse {
    let status: Int
    let retryAfter: String?
    let body: [UInt8]
}

private struct TransportFailure: Error {}

/// Each operation has one producer on Network's callback queue. The caller waits
/// outside that queue, with one absolute deadline for the whole attempt.
private final class Completion<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private let ready = DispatchSemaphore(value: 0)
    private var result: Result<Value, Error>?

    func finish(_ result: Result<Value, Error>) {
        lock.lock()
        defer { lock.unlock() }
        guard self.result == nil else { return }
        self.result = result
        ready.signal()
    }
    func wait(until deadline: DispatchTime) throws -> Value {
        guard ready.wait(timeout: deadline) == .success else { throw TransportFailure() }
        lock.lock()
        defer { lock.unlock() }
        guard let result else { throw TransportFailure() }
        return try result.get()
    }
}

final class HTTPClient: Sendable {
    private let queue = DispatchQueue(label: "onlyblocks.archive")

    func range(_ url: URL, _ range: String, _ cap: Int) throws -> RangeResponse {
        guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let host = parts.host else { throw DecodeFailure() }
        let tls = parts.scheme == "https"
        let portNumber = parts.port ?? (tls ? 443 : 80)
        guard let port = UInt16(exactly: portNumber).flatMap(NWEndpoint.Port.init(rawValue:)) else {
            throw DecodeFailure()
        }
        let endpoint = NWEndpoint.Host(host)
        let parameters: NWParameters
        if tls {
            let options = NWProtocolTLS.Options()
            sec_protocol_options_add_tls_application_protocol(options.securityProtocolOptions, "http/1.1")
            parameters = NWParameters(tls: options, tcp: NWProtocolTCP.Options())
        } else { parameters = .tcp }
        let connection = NWConnection(host: endpoint, port: port, using: parameters)
        defer { connection.cancel() }

        let deadline = DispatchTime.now() + 60
        let started = Completion<Bool>()
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: started.finish(.success(true))
            case .failed(let error), .waiting(let error): started.finish(.failure(error))
            case .cancelled: started.finish(.failure(TransportFailure()))
            default: break
            }
        }
        connection.start(queue: queue)
        _ = try started.wait(until: .now() + 10)
        connection.stateUpdateHandler = nil

        let hostHeader = parts.port.map { "\(host):\($0)" } ?? host
        let path = parts.percentEncodedPath.isEmpty ? "/" : parts.percentEncodedPath
        let target = path + (parts.percentEncodedQuery.map { "?\($0)" } ?? "")
        let request = "GET \(target) HTTP/1.1\r\nHost: \(hostHeader)\r\nRange: \(range)\r\n" +
            "User-Agent: onlyblocks/swift\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        let sent = Completion<Bool>()
        connection.send(content: Data(request.utf8), completion: .contentProcessed { error in
            if let error { sent.finish(.failure(error)) }
            else { sent.finish(.success(true)) }
        })
        _ = try sent.wait(until: deadline)

        var eof = false
        let input = HTTPInput {
            if eof { return [] }
            let received = Completion<(Data, Bool)>()
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 << 10) { bytes, _, complete, error in
                if let error, bytes?.isEmpty != false { received.finish(.failure(error)) }
                else { received.finish(.success((bytes ?? Data(), complete && error == nil))) }
            }
            let (bytes, complete) = try received.wait(until: deadline)
            eof = complete
            if bytes.isEmpty && !complete { throw TransportFailure() }
            return Array(bytes)
        }
        for _ in 0..<16 {
            let statusLine = try input.line().split(separator: " ", maxSplits: 2)
            guard statusLine.count >= 2, statusLine[0] == "HTTP/1.1" || statusLine[0] == "HTTP/1.0",
                  statusLine[1].utf8.count == 3, let status = Int(statusLine[1]), (100...999).contains(status) else {
                throw TransportFailure()
            }
            let headers = try input.headers()
            if (100...199).contains(status) && status != 101 { continue }
            let body: [UInt8]
            if status == 206 {
                do { body = try input.body(headers, cap, closeDelimited: true) }
                catch let error as HTTPError where error.status == 413 { throw DecodeFailure() }
            } else { body = [] }
            return RangeResponse(status: status, retryAfter: headers["retry-after"], body: body)
        }
        throw TransportFailure()
    }
}
