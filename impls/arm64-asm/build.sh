#!/usr/bin/env bash
# Assembles every hand-written .s file (defs.s is include-only) and links
# against libSystem and the OS-shipped libcurl (used only for https://).
set -euo pipefail
cd -- "$(dirname -- "$0")"
mkdir -p bin
objs=()
for src in *.s; do
    [[ $src == defs.s ]] && continue
    clang -arch arm64 -c "$src" -o "bin/${src%.s}.o"
    objs+=("bin/${src%.s}.o")
done
clang -arch arm64 -o bin/onlyblocks.tmp "${objs[@]}" -lcurl
mv -f bin/onlyblocks.tmp bin/onlyblocks
