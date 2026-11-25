#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -s .build/dotnet || ! -f build/OnlyBlocks.dll ]]; then
  bash ./build.sh
fi
IFS= read -r dotnet < .build/dotnet
export DOTNET_EnableDiagnostics=0
exec "$dotnet" build/OnlyBlocks.dll "$@"
