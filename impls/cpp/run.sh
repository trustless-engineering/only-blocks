#!/usr/bin/env bash
# Start the server in the foreground; `exec` hands SIGINT/SIGTERM straight to it.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/build/onlyblocks"
if [[ ! -x "$BIN" ]]; then
    bash "$DIR/build.sh" >&2
fi
exec "$BIN" "$@"
