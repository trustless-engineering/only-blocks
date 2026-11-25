#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -z ${ONLYBLOCKS_NIX_PHP:-} ]]; then
  export PATH="$HOME/.cargo/bin:$HOME/.nix-profile/bin:/opt/homebrew/bin:$PATH"
fi
if ! php -r 'exit(PHP_VERSION_ID >= 80100 && PHP_INT_SIZE === 8 && function_exists("pcntl_signal") && extension_loaded("openssl") ? 0 : 1);' 2>/dev/null; then
  if [[ -n ${ONLYBLOCKS_NIX_PHP:-} ]]; then
    echo "64-bit PHP 8.1+ with pcntl and OpenSSL is unavailable" >&2
    exit 1
  fi
  export ONLYBLOCKS_NIX_PHP=1
  exec nix --extra-experimental-features 'nix-command flakes' shell --offline nixpkgs#php -c bash ./build.sh
fi
mkdir -p .build
command -v php > .build/php
