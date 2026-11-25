#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
[[ -x build/onlyblocks ]] || bash build.sh
exec ./build/onlyblocks "$@"
