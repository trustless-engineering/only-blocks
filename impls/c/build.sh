#!/usr/bin/env bash
# Compile the zero-dependency C11 server. Only libc, pthreads and the OS-shipped libcurl
# (used solely for https:// Range transport, SPEC §3.3) are linked.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
CC="${CC:-clang}"
SRCS=(src/common.c src/json.c src/zstd.c src/ipld.c src/meta.c src/block.c src/upstream.c src/server.c)
# Rebuild only when a source or header is newer than the binary (idempotent and cheap).
if [[ -x build/onlyblocks ]]; then
    stale=0
    for f in src/*.c src/*.h build.sh; do [[ "$f" -nt build/onlyblocks ]] && stale=1; done
    [[ $stale -eq 0 ]] && exit 0
fi
"$CC" -O3 -std=c11 -Wall -Wextra ${EXTRA_CFLAGS:-} -o build/onlyblocks.tmp "${SRCS[@]}" -lpthread -lcurl
mv build/onlyblocks.tmp build/onlyblocks
