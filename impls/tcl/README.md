# OnlyBlocks in Tcl

Run with Homebrew Tcl 9 at `/opt/homebrew/bin/tclsh`.

```sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

The Tcl event loop and coroutines handle TCP connections and Range retries.
`binary scan` decodes fixed-width fields, Tcl integers preserve the full
unsigned 64-bit range, and tagged JSON values preserve numeric ID text.
The wire codecs and RFC 8878 Zstandard decoder use Tcl core commands.
The two LRUs keep their entries in Tcl arrays and use constant-time updates.

Plain HTTP stays in Tcl. HTTPS Range requests stream from macOS
`/usr/bin/curl` over a pipe.
