#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec bun run "$DIR/onlyblocks.ts" "$@"
