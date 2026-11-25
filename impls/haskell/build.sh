#!/usr/bin/env bash
# Compile with GHC alone. -hide-all-packages plus an explicit list of GHC boot
# packages makes the zero-dependency rule a compile-time guarantee.
set -euo pipefail
cd -- "$(dirname -- "$0")"
if command -v ghc >/dev/null 2>&1; then
    GHC=(ghc)
else
    GHC=(nix --extra-experimental-features 'nix-command flakes' --offline shell nixpkgs#ghc -c ghc)
fi
mkdir -p bin _build
"${GHC[@]}" -O2 -threaded -rtsopts '-with-rtsopts=-N2 -A8m' -j \
    -hide-all-packages \
    -package base -package bytestring -package containers -package array \
    -package unix -package process -package time \
    -outputdir _build -i. -o _build/onlyblocks Main.hs
mv -f _build/onlyblocks bin/onlyblocks
