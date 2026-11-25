#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ ! -x "$DIR/target/release/onlyblocks" ]]; then
    "$DIR/build.sh"
fi
exec "$DIR/target/release/onlyblocks" "$@"
