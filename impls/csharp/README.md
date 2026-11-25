# OnlyBlocks in C#

Use the .NET 8 SDK. To provision it with Nix, run
`nix shell nixpkgs#dotnet-sdk_8 -c dotnet --version` before the first build.
Run `./build.sh` and then `./run.sh --bind 127.0.0.1:8899` from this directory.
The build publishes a Release assembly offline and records the runtime path
so the launcher can exec .NET directly. Set `--base-url` or
`OLD_FAITHFUL_BASE_URL` to use a different archive origin.

The server uses `HttpListener`, `SocketsHttpHandler` and `System.Text.Json`
from the .NET base class library. Binary readers use `ReadOnlyMemory<byte>`
and spans to slice CAR, CBOR, Protobuf and transaction data in place. The
C# Zstd decoder verifies checksums and handles concatenated and skippable
frames with a 512 MiB output limit. Both LRUs are bounded and stay in RAM.

From the repository root, run `python3 conformance/runner.py --impl csharp`.
