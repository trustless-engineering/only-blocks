#!/bin/sh
set -eu
cd "$(dirname "$0")"
exec python3.11 -EBS server.py "$@"
