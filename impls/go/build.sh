#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
mkdir -p bin
export GOTOOLCHAIN=local CGO_ENABLED=0
go build -o bin/onlyblocks .
