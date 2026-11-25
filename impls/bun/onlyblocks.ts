import {
  Archive,
  type BlockOptions,
  BodyTooLarge,
  type Bytes,
  check,
  DETAILS,
  ENCODINGS,
  MiB,
  readBody,
  RpcError,
  U64_MAX,
  utf8,
} from './archive.ts';

// Runtime support for the JSON source-text proposal predates these TypeScript declarations.
type RawJson = { readonly rawJSON: string };
const exactJson = JSON as Omit<typeof JSON, 'parse'> & {
  parse(
    text: string,
    reviver: (key: string, value: unknown, context: { source: string }) => unknown,
  ): unknown;
  rawJSON(text: string): RawJson;
  isRawJSON(value: unknown): value is RawJson;
};

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && !exactJson.isRawJSON(value);
}

function jsonUnsigned(value: unknown, max: bigint): bigint | null {
  if (!exactJson.isRawJSON(value) || !/^(0|[1-9][0-9]{0,19})$/.test(value.rawJSON)) return null;
  const number = BigInt(value.rawJSON);
  return number <= max ? number : null;
}

function oneOf<T>(choices: readonly T[], value: unknown): value is T {
  return choices.some((choice) => choice === value);
}

function blockParams(params: unknown): BlockOptions & { slot: bigint } {
  const invalid = () => new RpcError(-32602, 'Invalid getBlock params');
  if (!Array.isArray(params) || params.length < 1 || params.length > 2) throw invalid();
  const slot = jsonUnsigned(params[0], U64_MAX);
  if (slot === null) throw invalid();
  const config: unknown = typeof params[1] === 'string' ? { encoding: params[1] } : params[1] ?? {};
  if (!object(config)) throw invalid();
  const encoding = config.encoding ?? 'json';
  const details = config.transactionDetails ?? 'full';
  const rewards = config.rewards ?? true;
  const maxVersion = jsonUnsigned(config.maxSupportedTransactionVersion, 255n);
  if (
    !oneOf(ENCODINGS, encoding) || !oneOf(DETAILS, details) ||
    (details === 'accounts' && encoding !== 'json') || typeof rewards !== 'boolean' ||
    (config.maxSupportedTransactionVersion != null && maxVersion === null) ||
    (config.commitment != null && !oneOf(['finalized', 'confirmed'], config.commitment))
  ) throw invalid();
  return { slot, encoding, details, rewards, maxVersion };
}

type Id = string | RawJson | null;
const rpcError = (id: Id, code: number, message: string) => ({
  jsonrpc: '2.0',
  error: { code, message },
  id,
});

async function dispatch(archive: Archive, request: unknown) {
  if (!object(request)) return rpcError(null, -32600, 'Invalid Request');
  const { jsonrpc, method, params, id = null } = request;
  if (
    (jsonrpc != null && typeof jsonrpc !== 'string') ||
    (method != null && typeof method !== 'string') ||
    (id !== null && typeof id !== 'string' && !exactJson.isRawJSON(id))
  ) return rpcError(null, -32600, 'Invalid Request');
  if (jsonrpc !== '2.0' || typeof method !== 'string') return rpcError(id, -32600, 'Invalid Request');

  try {
    if (method === 'getHealth') {
      if (params != null && !(Array.isArray(params) && params.length === 0)) {
        throw new RpcError(-32602, 'Invalid getHealth params');
      }
      return { jsonrpc: '2.0', result: 'ok', id };
    }
    if (method === 'getBlock') {
      const options = blockParams(params);
      return { jsonrpc: '2.0', result: await archive.getBlock(options.slot, options), id };
    }
    return rpcError(id, -32601, `Method not found: ${method}`);
  } catch (error) {
    if (error instanceof RpcError) return rpcError(id, error.code, error.message);
    return rpcError(
      id,
      -32603,
      error instanceof Error ? `Internal error: ${error.message}` : 'Internal error',
    );
  }
}

function jsonDepth(source: string): void {
  let depth = 0;
  let quoted = false;
  for (let i = 0; i < source.length; i++) {
    const char = source[i];
    if (char === '"') quoted = !quoted;
    else if (quoted && char === '\\') i++;
    else if (!quoted && (char === '[' || char === '{')) {
      check(++depth <= 128, 'JSON depth limit exceeded');
    } else if (!quoted && (char === ']' || char === '}')) depth--;
  }
}

async function rpc(archive: Archive, bytes: Bytes) {
  let request: unknown;
  try {
    const body = utf8.decode(bytes);
    jsonDepth(body);
    request = exactJson.parse(
      body,
      (_, value, context) => typeof value === 'number' ? exactJson.rawJSON(context.source) : value,
    );
  } catch {
    return rpcError(null, -32700, 'Parse error');
  }
  if (!Array.isArray(request)) return dispatch(archive, request);
  if (request.length < 1 || request.length > 100) return rpcError(null, -32600, 'Invalid Request');
  const replies = [];
  for (const item of request) replies.push(await dispatch(archive, item));
  return replies;
}

function jsonResponse(value: unknown): Response {
  const body = JSON.stringify(
    value,
    (_, entry: unknown) => typeof entry === 'bigint' ? exactJson.rawJSON(String(entry)) : entry,
  );
  return new Response(body, { headers: { 'Content-Type': 'application/json' } });
}

async function handlePost(archive: Archive, request: Request): Promise<Response> {
  if (Number(request.headers.get('content-length')) > MiB) {
    return new Response(null, { status: 413, headers: { Connection: 'close' } });
  }
  try {
    const body = await readBody(request.body, MiB);
    return jsonResponse(await rpc(archive, body.bytes));
  } catch (error) {
    if (error instanceof BodyTooLarge) {
      return new Response(null, { status: 413, headers: { Connection: 'close' } });
    }
    return jsonResponse(rpcError(null, -32603, 'Internal error'));
  }
}

function listenOptions(args: string[], bindEnv?: string, baseEnv?: string) {
  let bind = bindEnv ?? '127.0.0.1:8899';
  let baseUrl = baseEnv ?? 'https://files.old-faithful.net';
  for (let i = 0; i < args.length; i++) {
    const match = /^(--bind|--base-url)(?:=(.*))?$/s.exec(args[i]);
    check(match, `Unknown option: ${args[i]}`);
    const value = match[2] ?? args[++i];
    check(value !== undefined && !value.startsWith('--'), `Missing value for ${match[1]}`);
    if (match[1] === '--bind') bind = value;
    else baseUrl = value;
  }
  const address = /^(?:\[([^\]]+)\]|([^:]+)):([0-9]+)$/.exec(bind);
  check(address && Number(address[3]) <= 65535, 'Bind address must be HOST:PORT');
  const base = new URL(baseUrl.trim().replace(/\/+$/, ''));
  check(base.protocol === 'http:' || base.protocol === 'https:', 'Base URL must use HTTP or HTTPS');
  return { hostname: address[1] ?? address[2], port: Number(address[3]), base };
}

const { hostname, port, base } = listenOptions(
  Bun.argv.slice(2),
  Bun.env.ONLYBLOCKS_BIND,
  Bun.env.OLD_FAITHFUL_BASE_URL,
);
const shutdown = new AbortController();
const archive = new Archive(base, shutdown.signal);
const server = Bun.serve({
  hostname,
  port,
  development: false,
  // A retrying archive request can outlive Bun's default idle timeout.
  idleTimeout: 0,
  routes: {
    '/': {
      POST: (request) =>
        new URL(request.url).search ? new Response(null, { status: 404 }) : handlePost(archive, request),
    },
  },
  fetch(request) {
    const url = new URL(request.url);
    return url.pathname === '/' && !url.search
      ? new Response(null, { status: 405, headers: { Allow: 'POST' } })
      : new Response(null, { status: 404 });
  },
});

const stop = () => {
  if (shutdown.signal.aborted) return;
  shutdown.abort();
  void server.stop(true);
};
process.once('SIGINT', stop);
process.once('SIGTERM', stop);
