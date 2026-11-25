#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
/usr/bin/swiftc -swift-version 6 -O -whole-module-optimization -module-cache-path build/module-cache -o build/onlyblocks *.swift
