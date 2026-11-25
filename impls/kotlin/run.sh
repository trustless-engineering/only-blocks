#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
[[ -f build/onlyblocks.jar ]] || bash build.sh
exec java -XX:-UsePerfData -jar build/onlyblocks.jar "$@"
