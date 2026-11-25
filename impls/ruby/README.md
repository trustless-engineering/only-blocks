# OnlyBlocks in Ruby

Run with the system Ruby 2.6 on macOS.

```sh
./run.sh --bind 127.0.0.1:8899 --base-url https://files.old-faithful.net
```

The launcher disables RubyGems. The system runtime ships WEBrick, Net::HTTP,
OpenSSL and JSON. Binary Strings and `unpack1` handle fixed-width wire fields.
The wire codecs and RFC 8878 Zstandard decoder are implemented in Ruby.

Insertion-ordered Hashes provide bounded LRU caches. A SizedQueue limits
upstream attempts and releases its permit before retry backoff.
