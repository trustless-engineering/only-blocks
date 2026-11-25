#!/usr/bin/env bash
# Runs the Bash+AWK OnlyBlocks server in the foreground (exec, so signals reach it).
cd -- "$(dirname -- "$0")" || exit 1
if (( ${BASH_VERSINFO[0]:-0} < 5 )); then
    for candidate in /opt/homebrew/bin/bash "$HOME/.nix-profile/bin/bash" "$(command -v bash 2>/dev/null || true)"; do
        if [[ -n $candidate && -x $candidate ]] && "$candidate" -c '(( BASH_VERSINFO[0] >= 5 ))' 2>/dev/null; then
            exec "$candidate" ./server.bash "$@"
        fi
    done
fi
exec "${BASH:-bash}" ./server.bash "$@"
