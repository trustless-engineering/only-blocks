#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
[[ -x bin/onlyblocks ]] || bash build.sh >&2
exec ./bin/onlyblocks "$@"
