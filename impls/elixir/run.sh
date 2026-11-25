#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$HOME/.nix-profile/bin:/opt/homebrew/bin:$PATH"
[ -s _build/elixir_bin ] && [ -f _build/ebin/Elixir.OnlyBlocks.CLI.beam ] || bash build.sh >&2
bin="$(cat _build/elixir_bin)"
# No crash dumps on disk; +B makes SIGINT halt; SIGTERM runs a clean init:stop().
export ERL_CRASH_DUMP_SECONDS=0
exec "$bin/elixir" --no-halt --erl "+B -noinput" -pa _build/ebin -e 'OnlyBlocks.CLI.start(System.argv())' -- "$@"
