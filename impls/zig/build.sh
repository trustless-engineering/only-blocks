#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
mkdir -p bin
stage="$(mktemp -d bin/.build.XXXXXX)"
cleanup() {
    if [[ -f "$stage/onlyblocks" ]]; then
        unlink "$stage/onlyblocks"
    fi
    rmdir "$stage"
}
trap cleanup EXIT
nix shell nixpkgs#zig --offline -c zig build-exe main.zig -lc -O ReleaseSafe -femit-bin="$stage/onlyblocks"
mv -f -- "$stage/onlyblocks" bin/onlyblocks
