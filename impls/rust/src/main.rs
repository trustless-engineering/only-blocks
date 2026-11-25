use std::net::{TcpListener, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use onlyblocks::config::{self, Parsed};
use onlyblocks::old_faithful::OldFaithful;
use onlyblocks::rpc::Service;
use onlyblocks::{http_server, signal};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match config::parse(&args, |k| std::env::var(k).ok()) {
        Ok(Parsed::Run(c)) => c,
        Ok(Parsed::Exit(msg)) => {
            println!("{msg}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("onlyblocks: {e}");
            return ExitCode::from(2);
        }
    };

    let addrs: Vec<_> = match cfg.bind.to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => {
            eprintln!("onlyblocks: invalid bind address {:?}: {e}", cfg.bind);
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(&addrs[..]) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("onlyblocks: cannot bind {}: {e}", cfg.bind);
            return ExitCode::from(1);
        }
    };

    signal::install(Duration::from_millis(2500));

    let client = OldFaithful::new(cfg.base_url.clone(), cfg.client.clone());
    let service = Arc::new(Service::new(client, cfg.blockhash_cache_capacity));
    eprintln!(
        "onlyblocks: listening on http://{} (archive {}, 0 crates, RAM-only caches)",
        listener.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| cfg.bind.clone()),
        cfg.base_url.url
    );
    http_server::serve(listener, service);
    // `serve` only returns once shutdown was requested; the signal watcher exits the process.
    loop {
        std::thread::park();
    }
}
