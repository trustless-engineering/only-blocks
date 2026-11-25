#!/usr/bin/env bash
# Compile the standalone Elixir sources to .beam files with elixirc (no Mix,
# no Hex). The Elixir toolchain comes from PATH or the local Nix store; its
# bin directory is cached in _build/elixir_bin so run.sh never calls nix.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$HOME/.nix-profile/bin:/opt/homebrew/bin:$PATH"
mkdir -p _build

bin=""
if command -v elixirc >/dev/null 2>&1; then
  bin="$(dirname "$(command -v elixirc)")"
elif [ -s _build/elixir_bin ] && [ -x "$(cat _build/elixir_bin)/elixirc" ]; then
  bin="$(cat _build/elixir_bin)"
else
  find_bin='dirname "$(command -v elixirc)"'
  bin="$(nix shell --offline nixpkgs#elixir -c sh -c "$find_bin" 2>/dev/null ||
         nix shell nixpkgs#elixir -c sh -c "$find_bin")"
fi
printf '%s\n' "$bin" > _build/elixir_bin

rm -rf _build/ebin
mkdir -p _build/ebin
"$bin/elixirc" --ignore-module-conflict -o _build/ebin lib/*.ex
