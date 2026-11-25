#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]]; then
  export PATH="$JAVA_HOME/bin:$PATH"
elif [[ -x /opt/homebrew/opt/openjdk@17/bin/java ]]; then
  export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"
fi
[[ -f build/onlyblocks.jar ]] || bash build.sh
exec java -XX:-UsePerfData -jar build/onlyblocks.jar "$@"
