#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/javac" ]]; then
  export PATH="$JAVA_HOME/bin:$PATH"
elif [[ -x /opt/homebrew/opt/openjdk@17/bin/javac ]]; then
  export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
fi
mkdir -p build
javac --release 17 -d build *.java
