import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.time.Duration
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Flow
import java.util.concurrent.Semaphore
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

internal class RpcFailure(val code: Int, message: String) : RuntimeException(message)
internal data class BlockOptions(val encoding: String, val details: String, val rewards: Boolean, val maxVersion: ULong?)
private const val MAX_BODY = 1 shl 20
private const val MAX_SLICE = 128 shl 20
private const val ZERO_HASH = "11111111111111111111111111111111"

private class Lru<K, V> {
    private val entries = object : LinkedHashMap<K, V>(16, .75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?) = size > 100_000
    }
    @Synchronized fun get(key: K): V? = entries[key]
    @Synchronized fun put(key: K, value: V) { entries[key] = value }
}

private class RangeStatus(info: HttpResponse.ResponseInfo) : RuntimeException() {
    val code = info.statusCode()
    val retryAfter: String? = info.headers().firstValue("Retry-After").orElse(null)
}
private class RangeBody(private val cap: Int) : HttpResponse.BodySubscriber<ByteArray> {
    private val result = CompletableFuture<ByteArray>()
    private val out = ByteArrayOutputStream()
    private lateinit var subscription: Flow.Subscription
    override fun getBody() = result
    override fun onSubscribe(sub: Flow.Subscription) {
        subscription = sub
        sub.request(1)
    }
    override fun onNext(buffers: List<ByteBuffer>) {
        for (buf in buffers) {
            if (buf.remaining() > cap - out.size()) {
                result.completeExceptionally(DecodeFailure("Range body exceeds limit"))
                subscription.cancel()
                return
            }
            out.write(ByteArray(buf.remaining()).apply { buf.get(this) })
        }
        subscription.request(1)
    }
    override fun onError(error: Throwable) { result.completeExceptionally(error) }
    override fun onComplete() { result.complete(out.toByteArray()) }
}
private fun retryDelay(header: String?, failures: Int): Long {
    if (header != null) {
        header.trim().toULongOrNull()?.let { return minOf(it, 10uL).toLong() * 1000 }
        try {
            return Duration.between(ZonedDateTime.now(),
                ZonedDateTime.parse(header, DateTimeFormatter.RFC_1123_DATE_TIME)).toMillis().coerceIn(0, 10000)
        } catch (_: Exception) { }
    }
    val base = 200L shl failures
    return ThreadLocalRandom.current().nextLong(base / 2, base + 1)
}
private class Archive(private val base: String) {
    private data class Range(val offset: ULong, val length: Long)
    private val ranges = Lru<ULong, Range>()
    private val hashes = Lru<ULong, String>()
    private val permits = Semaphore(32)
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
        .version(HttpClient.Version.HTTP_1_1).build()

    private fun read(slot: ULong, suffix: String, first: ULong, length: Int, cap: Int): ByteArray {
        val tail = (length - 1).toULong()
        requireWire(first <= ULong.MAX_VALUE - tail)
        val epoch = slot / 432000uL
        val request = HttpRequest.newBuilder(URI.create("$base/$epoch/epoch-$epoch$suffix"))
            .timeout(Duration.ofSeconds(60)).header("User-Agent", "onlyblocks/kotlin")
            .header("Range", "bytes=$first-" + (first + tail)).GET().build()
        repeat(5) { failures ->
            var retryAfter: String? = null
            permits.acquire()
            try {
                val attempt = client.sendAsync(request) { info ->
                    if (info.statusCode() != 206) throw RangeStatus(info)
                    requireWire(info.headers().firstValueAsLong("Content-Length").orElse(0) <= cap, "Oversized range")
                    RangeBody(cap)
                }
                val response = try { attempt.get(60, TimeUnit.SECONDS) } catch (_: TimeoutException) {
                    attempt.cancel(true)
                    null
                } catch (e: ExecutionException) {
                    val cause = generateSequence(e as Throwable) { it.cause }
                        .firstOrNull { it is DecodeFailure || it is RangeStatus }
                    when (cause) {
                        is DecodeFailure -> throw cause
                        is RangeStatus -> when (cause.code) {
                            404 -> throw RpcFailure(-32004, "Block not available for slot $slot")
                            429, in 500..599 -> retryAfter = cause.retryAfter
                            else -> throw DecodeFailure("Unexpected archive HTTP status ${cause.code}")
                        }
                    }
                    null
                } catch (e: InterruptedException) {
                    attempt.cancel(true)
                    throw e
                }
                if (response != null) {
                    requireWire(response.body().size == length, "Unexpected range length")
                    return response.body()
                }
            } finally { permits.release() }
            if (failures < 4) Thread.sleep(retryDelay(retryAfter, failures))
        }
        throw DecodeFailure("Archive range retries exhausted")
    }

    private fun load(slot: ULong): Car {
        val range = ranges.get(slot) ?: Bytes(read(slot, "-slot-ranges.raw", (slot % 432000uL) * 12uL, 12, 12))
            .let { Range(it.u64(), it.u32()) }.also { ranges.put(slot, it) }
        if (range.length == 0L) throw RpcFailure(-32007, "Slot $slot was skipped")
        requireWire(range.length <= MAX_SLICE)
        return Car(read(slot, ".car", range.offset, range.length.toInt(), MAX_SLICE))
    }
    private fun hash(slot: ULong, car: Car, entries: List<Cid>): String {
        val hash = entries.lastOrNull()?.let { (car.get(it, 1uL).getOrNull(2) as? ByteArray
            ?: throw DecodeFailure("Missing entry hash")).pubkey() } ?: ZERO_HASH
        hashes.put(slot, hash)
        return hash
    }
    fun block(slot: ULong, options: BlockOptions): Obj {
        val car = load(slot)
        val block = car.block
        requireWire(block[1] == slot, "Block slot mismatch")
        val entries = links(block.getOrNull(3))
        val info = (block.getOrNull(4) as? List<*>).orEmpty()
        val parent = info.getOrNull(0) as? ULong ?: 0uL
        val current = hash(slot, car, entries)
        val previous = if (slot == 0uL) ZERO_HASH else hashes.get(parent) ?: load(parent).let {
            hash(parent, it, links(it.block.getOrNull(3)))
        }
        val time = when (val time = info.getOrNull(1)) {
            is Long -> time
            is ULong -> if (time <= Long.MAX_VALUE.toULong()) time.toLong() else null
            else -> null
        }
        val result = obj("previousBlockhash" to previous, "blockhash" to current, "parentSlot" to unsigned(parent),
            "blockTime" to time?.takeIf { it != 0L }, "blockHeight" to (info.getOrNull(2) as? ULong)?.let(::unsigned))
        if (options.details != "none") {
            val signaturesOnly = options.details == "signatures"
            val items = ArrayList<Any>()
            for (key in entries) {
                val entry = car.get(key, 1uL)
                requireWire((entry.getOrNull(2) as? ByteArray)?.size == 32)
                for (txKey in links(entry.getOrNull(3))) {
                    val node = car.get(txKey, 0uL)
                    val tx = Transaction(car.payload(node.getOrNull(1)))
                    if (signaturesOnly) items.add(tx.signatures.first().b58())
                    else {
                        val meta = node.getOrNull(2)?.takeIf { it is List<*> }?.let { metadata(slot, car.payload(it)) }
                        items.add(tx.json(meta, options))
                    }
                }
            }
            result[if (signaturesOnly) "signatures" else "transactions"] = items
        }
        if (options.rewards) {
            val rewards = (block.getOrNull(5) as? ByteArray)?.let(::link)?.takeUnless { it.absent }
                ?.let { car.find(it, 5uL) }
            val bytes = if (rewards != null && rewards.size > 2) car.payload(rewards[2]) else byteArrayOf()
            result.putAll(rewards(slot, bytes))
        }
        return result
    }
}

private fun invalid(): Nothing = throw RpcFailure(-32602, "Invalid params")
private fun blockParams(value: Any?): Pair<ULong, BlockOptions> {
    val params = value as? List<*> ?: invalid()
    if (params.size !in 1..2) invalid()
    val slot = (params[0] as? JsonNumber)?.asUnsigned() ?: invalid()
    val config = when (val cfg = params.getOrNull(1)) {
        null -> emptyMap<String, Any?>()
        is String -> mapOf("encoding" to cfg)
        is Map<*, *> -> cfg
        else -> invalid()
    }
    fun str(key: String, default: String, choices: Set<String>): String {
        val v = config[key] ?: return default
        return if (v is String && v in choices) v else invalid()
    }
    val encoding = str("encoding", "json", setOf("json", "jsonParsed", "base64", "base58"))
    val details = str("transactionDetails", "full", setOf("full", "accounts", "signatures", "none"))
    if (details == "accounts" && encoding != "json") invalid()
    str("commitment", "finalized", setOf("finalized", "confirmed"))
    val rewards = config["rewards"]?.let { it as? Boolean ?: invalid() } ?: true
    val version = config["maxSupportedTransactionVersion"]?.let {
        (it as? JsonNumber)?.asUnsigned()?.takeIf { n -> n <= 255uL } ?: invalid()
    }
    return slot to BlockOptions(encoding, details, rewards, version)
}
private fun rpcError(id: Any?, code: Int, message: String) =
    obj("jsonrpc" to "2.0", "id" to id, "error" to obj("code" to code, "message" to message))
private fun dispatch(archive: Archive, value: Any?): Obj {
    val invalid = "Invalid Request"
    val request = value as? Map<*, *> ?: return rpcError(null, -32600, invalid)
    val protocol = request["jsonrpc"]
    val method = request["method"]
    val id = request["id"]
    if ((protocol != null && protocol !is String) || (method != null && method !is String) ||
        (id != null && id !is String && id !is JsonNumber)) return rpcError(null, -32600, invalid)
    if (protocol != "2.0" || method !is String) return rpcError(id, -32600, invalid)
    return try {
        val params = request["params"]
        val result = when (method) {
            "getHealth" -> if (params == null || params is List<*> && params.isEmpty()) "ok" else invalid()
            "getBlock" -> blockParams(params).let { (slot, options) -> archive.block(slot, options) }
            else -> throw RpcFailure(-32601, "Method not found: $method")
        }
        obj("jsonrpc" to "2.0", "id" to id, "result" to result)
    } catch (e: RpcFailure) {
        rpcError(id, e.code, e.message ?: "RPC error")
    } catch (_: Exception) {
        rpcError(id, -32603, "Internal error")
    }
}
private fun rpc(archive: Archive, body: ByteArray): Any {
    val value = try { Json(utf8(body)).parse() } catch (_: Exception) {
        return rpcError(null, -32700, "Parse error")
    }
    return if (value is List<*>) {
        if (value.size !in 1..100) rpcError(null, -32600, "Invalid Request")
        else value.map { dispatch(archive, it) }
    } else dispatch(archive, value)
}
private fun serve(exchange: HttpExchange, archive: Archive) {
    exchange.use { e ->
        e.responseHeaders.set("Connection", "close")
        if (e.requestURI.rawPath != "/") { e.sendResponseHeaders(404, -1); return }
        if (e.requestMethod != "POST") { e.sendResponseHeaders(405, -1); return }
        if ((e.requestHeaders.getFirst("Content-Length")?.toLongOrNull() ?: 0) > MAX_BODY) {
            e.sendResponseHeaders(413, -1)
            return
        }
        val body = e.requestBody.readNBytes(MAX_BODY + 1)
        if (body.size > MAX_BODY) { e.sendResponseHeaders(413, -1); return }
        val output = encodeJson(rpc(archive, body))
        e.responseHeaders.set("Content-Type", "application/json")
        e.sendResponseHeaders(200, output.size.toLong())
        e.responseBody.write(output)
    }
}

fun main(args: Array<String>) {
    var bind = System.getenv("ONLYBLOCKS_BIND") ?: "127.0.0.1:8899"
    var base = System.getenv("OLD_FAITHFUL_BASE_URL") ?: "https://files.old-faithful.net"
    var i = 0
    while (i < args.size) {
        val arg = args[i++]
        val key = arg.substringBefore('=')
        require(key == "--bind" || key == "--base-url") { "Unknown argument $key" }
        val value = if ('=' in arg) arg.substringAfter('=') else args.getOrNull(i++) ?: error("Missing $key value")
        if (key == "--bind") bind = value else base = value
    }
    base = base.trim().trimEnd('/')
    val uri = URI.create(base)
    require(uri.scheme in setOf("http", "https") && uri.host != null)
    val host = bind.substringBeforeLast(':').removeSurrounding("[", "]")
    val port = bind.substringAfterLast(':').toInt()
    val archive = Archive(base)
    val executor = Executors.newFixedThreadPool(40)
    val server = HttpServer.create(InetSocketAddress(host, port), 128)
    server.executor = executor
    server.createContext("/") { serve(it, archive) }
    Runtime.getRuntime().addShutdownHook(Thread {
        server.stop(0)
        executor.shutdownNow()
    })
    server.start()
}
