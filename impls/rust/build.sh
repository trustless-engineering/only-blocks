#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release --manifest-path "$(dirname "$0")/Cargo.toml"
