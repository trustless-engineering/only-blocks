#!/bin/sh
set -eu
for candidate in /opt/homebrew/bin/tclsh /opt/homebrew/opt/tcl-tk/bin/tclsh "$(command -v tclsh 2>/dev/null || true)"; do
  if [ -n "$candidate" ] && [ -x "$candidate" ]; then
    exec "$candidate" "$(dirname "$0")/server.tcl" "$@"
  fi
done
echo "tclsh not found" >&2
exit 1
