#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ ! -x bin/onlyblocks ]]; then bash build.sh >&2; fi
exec ./bin/onlyblocks "$@"
