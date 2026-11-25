#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -s .build/php ]]; then
  bash ./build.sh
fi
IFS= read -r php < .build/php
exec "$php" -d memory_limit=-1 -d opcache.enable_cli=0 -d serialize_precision=-1 server.php "$@"
