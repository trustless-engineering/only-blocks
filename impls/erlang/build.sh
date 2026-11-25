#!/usr/bin/env bash
# Compile the pure-OTP sources to .beam files (no rebar3, no Hex).
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$HOME/.nix-profile/bin:/opt/homebrew/bin:$PATH"
mkdir -p ebin
erlc +warn_unused_vars -o ebin src/*.erl
