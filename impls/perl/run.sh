#!/bin/sh
set -eu
exec /usr/bin/perl -I "$(dirname "$0")" "$(dirname "$0")/server.pl" "$@"
