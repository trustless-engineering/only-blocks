#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PATH="/opt/homebrew/opt/openjdk@17/bin:$HOME/.nix-profile/bin:/opt/homebrew/bin:$PATH"
export JAVA_HOME="$(dirname "$(dirname "$(command -v javac)")")"
mkdir -p build
if command -v kotlinc >/dev/null; then
    compiler=(kotlinc)
else
    compiler=(nix --extra-experimental-features 'nix-command flakes' --offline shell nixpkgs#kotlin -c kotlinc)
fi
"${compiler[@]}" -jvm-target 17 -include-runtime -d build/onlyblocks.jar *.kt
