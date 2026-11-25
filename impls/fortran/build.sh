#!/usr/bin/env bash
# Compile the OnlyBlocks Fortran 2018 server (and, with --test, the offline self-test).
set -euo pipefail
cd -- "$(dirname -- "$0")"

FC="${FC:-gfortran}"
if [[ -x /opt/homebrew/bin/gfortran ]]; then FC=/opt/homebrew/bin/gfortran; fi

FLAGS=(-O3 -std=f2018 -ffree-line-length-none -fwrapv)
LINK=()
if [[ "$(uname -s)" == "Darwin" ]]; then
    # Homebrew GCC derives -mmacosx-version-min from the kernel version, which
    # newer clang/ld reject; pin a deployment target and the SDK sysroot.
    export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
    SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
    if [[ -n "$SDK" ]]; then LINK=(-isysroot "$SDK" -L"$SDK/usr/lib"); fi
fi
if [[ "${1:-}" == "--debug" || -n "${OB_DEBUG:-}" ]]; then
    FLAGS=(-O0 -g -std=f2018 -ffree-line-length-none -fwrapv -fcheck=all -fbacktrace)
fi

# Dependency order: each module only uses modules listed before it.
SRC=(ob_util ob_hash ob_zstd ob_codec ob_json ob_posix ob_http ob_cache ob_car ob_tx ob_meta ob_render ob_rpc ob_server)

mkdir -p build bin
objs=()
for m in "${SRC[@]}"; do
    "$FC" "${FLAGS[@]}" -Jbuild -c "src/$m.f90" -o "build/$m.o"
    objs+=("build/$m.o")
done
"$FC" "${FLAGS[@]}" -Jbuild -c src/main.f90 -o build/main.o
"$FC" "${FLAGS[@]}" "${LINK[@]}" "${objs[@]}" build/main.o -o bin/onlyblocks.tmp
mv -f bin/onlyblocks.tmp bin/onlyblocks

if [[ "${1:-}" == "--test" ]]; then
    "$FC" "${FLAGS[@]}" -Jbuild -c tests/selftest.f90 -o build/selftest.o
    "$FC" "${FLAGS[@]}" "${LINK[@]}" build/ob_util.o build/ob_hash.o build/ob_zstd.o build/ob_codec.o \
        build/selftest.o -o bin/selftest
    ./bin/selftest
fi
