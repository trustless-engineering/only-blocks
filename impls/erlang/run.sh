#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$HOME/.nix-profile/bin:/opt/homebrew/bin:$PATH"
[ -f ebin/onlyblocks.beam ] || bash build.sh >&2
# No crash dumps on disk; +B makes SIGINT halt; SIGTERM runs init:stop().
export ERL_CRASH_DUMP_SECONDS=0
exec erl -noshell -noinput +B -boot start_clean -pa ebin -eval 'onlyblocks:start()' -extra "$@"
