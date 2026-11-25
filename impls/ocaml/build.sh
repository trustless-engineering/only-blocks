#!/usr/bin/env bash
# Compile with the stock OCaml native compiler: stdlib + unix + threads only, no OPAM.
set -euo pipefail
cd -- "$(dirname -- "$0")"
SOURCES=(zstd.ml wire.ml meta.ml json.ml http.ml main.ml)
if command -v ocamlopt >/dev/null 2>&1; then
    OCAMLOPT=(ocamlopt)
else
    OCAMLOPT=(nix --extra-experimental-features 'nix-command flakes' --offline shell nixpkgs#ocaml -c ocamlopt)
fi
mkdir -p _build bin
cp -f "${SOURCES[@]}" _build/
(
    cd _build
    "${OCAMLOPT[@]}" -O2 -I +unix -I +threads unix.cmxa threads.cmxa "${SOURCES[@]}" -o onlyblocks.new
)
mv -f _build/onlyblocks.new bin/onlyblocks
