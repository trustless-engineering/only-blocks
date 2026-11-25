#!/usr/bin/env bash
# Build the zero-crate OnlyBlocks server. `--offline` proves nothing is downloaded:
# Cargo.toml has no [dependencies], so the standard library is all there is.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$HOME/.nix-profile/bin:/opt/homebrew/bin:$PATH"
cd "$(dirname "$0")"
cargo build --release --offline --quiet
