//! Command-line and environment configuration (SPEC.md §2.3): flag > environment > default.

use std::time::Duration;

use crate::http_client::{parse_base_url, BaseUrl};
use crate::old_faithful::ClientConfig;

pub const DEFAULT_BIND: &str = "127.0.0.1:8899";
pub const DEFAULT_BASE_URL: &str = "https://files.old-faithful.net";

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub base_url: BaseUrl,
    pub client: ClientConfig,
    pub blockhash_cache_capacity: usize,
}

pub const USAGE: &str = "\
onlyblocks — zero-crate historical Solana getBlock JSON-RPC server backed by Old Faithful

USAGE:
    onlyblocks [OPTIONS]

OPTIONS:
    --bind <HOST:PORT>                   listen address   [env ONLYBLOCKS_BIND, default 127.0.0.1:8899]
    --base-url <URL>                     archive base URL [env OLD_FAITHFUL_BASE_URL, default https://files.old-faithful.net]
    --max-slice-bytes <N>                largest CAR slice to fetch (default 134217728)
    --max-concurrent-requests <N>        upstream requests in flight (default 32)
    --slot-range-cache-capacity <N>      slot -> range LRU entries (default 100000, 0 disables)
    --blockhash-cache-capacity <N>       slot -> blockhash LRU entries (default 100000, 0 disables)
    --max-retries <N>                    retries on 429/5xx/transport errors (default 4)
    --connect-timeout-secs <N>           upstream connect timeout (default 10)
    --request-timeout-secs <N>           upstream per-attempt timeout (default 60)
    -h, --help                           print this help
    -V, --version                        print the version
";

pub enum Parsed {
    Run(Config),
    Exit(String),
}

fn number<T: std::str::FromStr>(flag: &str, v: &str) -> Result<T, String> {
    v.parse::<T>().map_err(|_| format!("invalid value {v:?} for {flag}"))
}

/// Parse `args` (without the program name) and the environment lookup `env`.
pub fn parse(args: &[String], env: impl Fn(&str) -> Option<String>) -> Result<Parsed, String> {
    let mut bind: Option<String> = None;
    let mut base: Option<String> = None;
    let mut client = ClientConfig::default();
    let mut blockhash_cache_capacity = 100_000usize;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        i += 1;
        if arg == "-h" || arg == "--help" {
            return Ok(Parsed::Exit(USAGE.to_string()));
        }
        if arg == "-V" || arg == "--version" {
            return Ok(Parsed::Exit(format!("onlyblocks {}", env!("CARGO_PKG_VERSION"))));
        }
        let Some(flag_body) = arg.strip_prefix("--") else {
            return Err(format!("unexpected argument {arg:?}\n\n{USAGE}"));
        };
        let (name, inline) = match flag_body.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (flag_body, None),
        };
        const KNOWN: [&str; 9] = [
            "bind",
            "base-url",
            "max-slice-bytes",
            "max-concurrent-requests",
            "slot-range-cache-capacity",
            "blockhash-cache-capacity",
            "max-retries",
            "connect-timeout-secs",
            "request-timeout-secs",
        ];
        if !KNOWN.contains(&name) {
            return Err(format!("unknown flag --{name}\n\n{USAGE}"));
        }
        let value = match inline {
            Some(v) => v,
            None => {
                let Some(v) = args.get(i) else { return Err(format!("missing value for --{name}")) };
                i += 1;
                v.clone()
            }
        };
        let flag = format!("--{name}");
        match name {
            "bind" => bind = Some(value),
            "base-url" => base = Some(value),
            "max-slice-bytes" => client.max_slice_bytes = number(&flag, &value)?,
            "max-concurrent-requests" => client.max_concurrent_requests = number(&flag, &value)?,
            "slot-range-cache-capacity" => client.slot_range_cache_capacity = number(&flag, &value)?,
            "blockhash-cache-capacity" => blockhash_cache_capacity = number(&flag, &value)?,
            "max-retries" => client.max_retries = number(&flag, &value)?,
            "connect-timeout-secs" => client.connect_timeout = Duration::from_secs(number(&flag, &value)?),
            "request-timeout-secs" => client.request_timeout = Duration::from_secs(number(&flag, &value)?),
            _ => return Err(format!("unknown flag --{name}\n\n{USAGE}")),
        }
    }
    let bind = bind.or_else(|| env("ONLYBLOCKS_BIND")).unwrap_or_else(|| DEFAULT_BIND.to_string());
    let base = base.or_else(|| env("OLD_FAITHFUL_BASE_URL")).unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    let base_url = parse_base_url(&base)?;
    if client.max_slice_bytes == 0 || client.max_concurrent_requests == 0 {
        return Err("--max-slice-bytes and --max-concurrent-requests must be > 0".into());
    }
    if client.connect_timeout.is_zero() || client.request_timeout.is_zero() {
        return Err("timeouts must be > 0".into());
    }
    Ok(Parsed::Run(Config { bind, base_url, client, blockhash_cache_capacity }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str], env: &[(&str, &str)]) -> Result<Config, String> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let env: Vec<(String, String)> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        match parse(&args, |k| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))? {
            Parsed::Run(c) => Ok(c),
            Parsed::Exit(m) => Err(m),
        }
    }

    #[test]
    fn precedence_and_forms() {
        let c = run(&[], &[]).unwrap();
        assert_eq!(c.bind, DEFAULT_BIND);
        assert_eq!(c.base_url.url, DEFAULT_BASE_URL);
        let c = run(&[], &[("ONLYBLOCKS_BIND", "0.0.0.0:1"), ("OLD_FAITHFUL_BASE_URL", "http://x:2/")]).unwrap();
        assert_eq!((c.bind.as_str(), c.base_url.url.as_str()), ("0.0.0.0:1", "http://x:2"));
        let c = run(&["--bind", "127.0.0.1:3", "--base-url=http://y"], &[("ONLYBLOCKS_BIND", "0.0.0.0:1")]).unwrap();
        assert_eq!((c.bind.as_str(), c.base_url.url.as_str()), ("127.0.0.1:3", "http://y"));
        assert!(run(&["--bogus", "1"], &[]).is_err());
        assert!(run(&["--base-url", "ftp://x"], &[]).is_err());
        assert!(run(&["--bind"], &[]).is_err());
    }
}
