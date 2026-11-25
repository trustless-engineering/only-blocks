#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -z ${ONLYBLOCKS_NIX_DOTNET:-} ]]; then
  export PATH="$HOME/.cargo/bin:$HOME/.nix-profile/bin:/opt/homebrew/bin:$PATH"
fi
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true DOTNET_GENERATE_ASPNET_CERTIFICATE=false
export DOTNET_CLI_HOME="$PWD/.build"
if ! command -v dotnet >/dev/null || ! dotnet --list-sdks | grep -E '^8\.' >/dev/null; then
  if [[ -n ${ONLYBLOCKS_NIX_DOTNET:-} ]]; then
    echo ".NET 8 SDK is unavailable" >&2
    exit 1
  fi
  export ONLYBLOCKS_NIX_DOTNET=1
  exec nix --extra-experimental-features 'nix-command flakes' shell --offline nixpkgs#dotnet-sdk_8 -c bash ./build.sh
fi
dotnet publish OnlyBlocks.csproj -c Release -o build --disable-build-servers -p:RestoreSources="$PWD"
command -v dotnet > .build/dotnet
