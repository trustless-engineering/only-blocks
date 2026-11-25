#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
mkdir -p build
javac --release 17 -d build *.java
