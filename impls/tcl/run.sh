#!/bin/sh
set -eu
exec /opt/homebrew/bin/tclsh "$(dirname "$0")/server.tcl" "$@"
