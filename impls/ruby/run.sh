#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec /usr/bin/ruby --disable=gems,rubyopt server.rb "$@"
