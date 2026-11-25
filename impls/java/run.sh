#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
[[ -f build/onlyblocks/Server.class ]] || bash build.sh
exec java -XX:-UsePerfData -cp build onlyblocks.Server "$@"
