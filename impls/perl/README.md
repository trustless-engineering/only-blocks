# OnlyBlocks in Perl 5

Run with macOS system Perl and native 64-bit integers.

```sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

Core Perl modules provide TCP sockets, JSON escaping, Base64, and timers.
The binary codecs use `pack`, `unpack`, and `vec`. The Zstandard decoder
implements RFC 8878 in Perl, including FSE, Huffman literals, concatenated
frames, and checksums. The two RAM-only LRUs update in constant time.

The server handles one connection at a time. Plain HTTP stays in Perl.
HTTPS Range requests stream from macOS `/usr/bin/curl` over a pipe.
