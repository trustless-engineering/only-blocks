#!/usr/bin/env bash
# Starts the ARM64 assembly OnlyBlocks server in the foreground.
cd -- "$(dirname -- "$0")" || exit 1
[[ -x bin/onlyblocks ]] || bash ./build.sh >&2 || exit 1
exec ./bin/onlyblocks "$@"
