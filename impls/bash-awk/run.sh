#!/usr/bin/env bash
# Runs the Bash+AWK OnlyBlocks server in the foreground (exec, so signals reach it).
cd -- "$(dirname -- "$0")" || exit 1
exec "${BASH:-bash}" ./server.bash "$@"
