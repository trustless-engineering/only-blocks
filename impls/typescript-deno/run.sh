#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export DENO_NO_UPDATE_CHECK=1
exec deno run --allow-net --allow-env "$DIR/onlyblocks.ts" "$@"
