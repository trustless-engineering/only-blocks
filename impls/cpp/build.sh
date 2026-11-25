#!/usr/bin/env bash
# Compile the zero-dependency C++20 server. Only the C++ standard library, libc and the
# OS-shipped libcurl (solely for https:// Range transport, SPEC §3.3) are linked.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
CXX="${CXX:-clang++}"
SRCS=(src/core.cpp src/json.cpp src/zstd.cpp src/ipld.cpp src/solana.cpp src/archive.cpp src/block.cpp src/main.cpp)
# Rebuild only when a source or header is newer than the binary (idempotent and cheap).
if [[ -x build/onlyblocks ]]; then
    stale=0
    for f in src/*.cpp src/*.hpp build.sh; do [[ "$f" -nt build/onlyblocks ]] && stale=1; done
    [[ $stale -eq 0 ]] && exit 0
fi
"$CXX" -O3 -std=c++20 -Wall -Wextra ${EXTRA_CXXFLAGS:-} -o build/onlyblocks.tmp "${SRCS[@]}" -lcurl
mv build/onlyblocks.tmp build/onlyblocks
