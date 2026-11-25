# server.bash: OnlyBlocks HTTP front end in GNU Bash 5.3.
#
# Bash owns the sockets: the `accept` loadable builtin (shipped with bash)
# listens, one forked subshell per connection frames HTTP/1.1, and a single
# long-lived AWK coprocess (main.awk) holds both LRU caches and does all the
# decoding, Zstandard included (zstd.awk). Nothing touches the disk: requests
# and replies cross anonymous pipes, never here-documents, here-strings, FIFOs
# or temp files.

export LC_ALL=C
DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

die() { printf 'onlyblocks-bash-awk: %s\n' "$*" >&2; exit 1; }

bind=${ONLYBLOCKS_BIND:-127.0.0.1:8899}
base=${OLD_FAITHFUL_BASE_URL:-https://files.old-faithful.net}
while (($#)); do
    case $1 in
        --bind=*) bind=${1#*=} ;;
        --base-url=*) base=${1#*=} ;;
        --bind | --base-url)
            (($# >= 2)) || die "missing value for $1"
            if [[ $1 == --bind ]]; then bind=$2; else base=$2; fi
            shift ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

# --base-url: trim surrounding whitespace, strip trailing slashes, http(s) only.
base=${base#"${base%%[![:space:]]*}"}
base=${base%"${base##*[![:space:]]}"}
while [[ $base == */ ]]; do base=${base%/}; done
[[ $base =~ ^https?://[^/]+ ]] || die "--base-url must be an http:// or https:// URL"

[[ $bind =~ ^\[.*\]:[0-9]+$ ]] && die "IPv6 bind addresses are not supported by the accept builtin"
[[ $bind =~ ^([^:]+):([0-9]+)$ ]] || die "--bind must be HOST:PORT"
host=${BASH_REMATCH[1]} port=${BASH_REMATCH[2]}
((10#$port <= 65535)) || die "bad port in --bind"
[[ $host == localhost ]] && host=127.0.0.1

loadables=$(dirname -- "$(readlink -f -- "$BASH")")/../lib/bash
enable -f accept accept 2>/dev/null || enable -f "$loadables/accept" accept 2>/dev/null || enable -f /opt/homebrew/lib/bash/accept accept 2>/dev/null ||
    die "this bash ($BASH_VERSION) does not ship the 'accept' loadable builtin"
enable -f sleep sleep 2>/dev/null || enable -f "$loadables/sleep" sleep 2>/dev/null || enable -f /opt/homebrew/lib/bash/sleep sleep 2>/dev/null ||
    sleep() { /bin/sleep "$@"; }

export OB_BASE=$base OB_DIR=$DIR OB_BASH=$BASH
export OB_OD=/usr/bin/od OB_CURL=/usr/bin/curl

coproc ENGINE {
    exec /usr/bin/awk -f "$DIR/lib.awk" -f "$DIR/json.awk" -f "$DIR/wire.awk" \
        -f "$DIR/zstd.awk" -f "$DIR/meta.awk" -f "$DIR/main.awk"
}
exec {TO}>&"${ENGINE[1]}" {FROM}<&"${ENGINE[0]}"

reply_status() {
    printf 'HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' "$2" >&"$1"
}

reply_json() {
    printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
        "${#2}" "$2" >&"$1"
}

# read_exact FD COUNT: appends exactly COUNT bytes to $body. Bash variables
# cannot hold NUL, and `read -N` silently skips NULs and then waits for more
# input, so NUL is made the delimiter instead: every early stop is a NUL,
# which is counted as one byte and recorded in $nul.
read_exact() {
    local fd=$1 remaining=$2 chunk
    while ((remaining > 0)); do
        IFS= read -r -d '' -n "$remaining" -t 30 -u "$fd" chunk || return 1
        body+=$chunk
        if ((${#chunk} < remaining)); then
            nul=1
            ((remaining -= ${#chunk} + 1))
        else
            ((remaining -= ${#chunk}))
        fi
    done
    return 0
}

# One connection, in a forked subshell: parse the request, hand the body to
# the engine, relay its reply.
handle() {
    local fd=$1 seq=$2 line method target name value cl= te= body= n total=0 head resp hdrs=0 nul=0
    trap '' PIPE
    IFS= read -r -t 10 -u "$fd" line || return
    line=${line%$'\r'}
    method=${line%% *}
    target=${line#* }
    target=${target%% *}
    while IFS= read -r -t 10 -u "$fd" line; do
        line=${line%$'\r'}
        [[ -z $line ]] && break
        ((++hdrs > 256)) && { reply_status "$fd" "431 Request Header Fields Too Large"; return; }
        name=${line%%:*}
        value=${line#*:}
        value=${value#"${value%%[![:space:]]*}"}
        value=${value%"${value##*[![:space:]]}"}
        case ${name,,} in
            content-length) cl=$value ;;
            transfer-encoding) te=${value,,} ;;
        esac
    done
    [[ $target == / ]] || { reply_status "$fd" "404 Not Found"; return; }
    [[ $method == POST ]] || { reply_status "$fd" "405 Method Not Allowed"; return; }
    if [[ $te == *chunked* ]]; then
        while :; do
            IFS= read -r -t 10 -u "$fd" line || return
            line=${line%$'\r'}
            line=${line%%;*}
            [[ $line =~ ^[0-9a-fA-F]{1,8}$ ]] || { reply_status "$fd" "400 Bad Request"; return; }
            n=$((16#$line))
            ((n == 0)) && break
            ((total += n, total > 1048576)) && { reply_status "$fd" "413 Payload Too Large"; return; }
            read_exact "$fd" "$n" || return
            IFS= read -r -t 10 -u "$fd" line || return
        done
        while IFS= read -r -t 10 -u "$fd" line && [[ -n ${line%$'\r'} ]]; do :; done
    elif [[ -n $cl ]]; then
        [[ $cl =~ ^[0-9]+$ ]] || { reply_status "$fd" "400 Bad Request"; return; }
        ((${#cl} > 9 || 10#$cl > 1048576)) && { reply_status "$fd" "413 Payload Too Large"; return; }
        read_exact "$fd" "$((10#$cl))" || return
    fi
    # JSON never contains a raw NUL or U+0001; the engine frames bodies with
    # U+0001, so either one is answered here as a parse error.
    if ((nul)) || [[ $body == *$'\001'* ]]; then
        reply_json "$fd" '{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}'
        return
    fi
    printf 'Q %s %d\n%s\001' "$seq" "${#body}" "$body" >&"$TO"
    while :; do
        IFS= read -r -u "$FROM" head || return
        IFS= read -r -u "$FROM" resp || return
        [[ $head == "R $seq "* ]] && break
    done
    reply_json "$fd" "$resp"
}

# Single-threaded accept loop. `accept` closes its listening socket once a
# client connects, so the connection is handed to a background handler
# straight away and the port is listening again long before that handler
# replies. Handlers run one at a time (wait for the previous one first), which
# keeps the engine's pipes strictly request/reply.
serve() {
    local seq=0 prev= fails=0 fd
    while :; do
        if ! accept -b "$host" -v fd "$port" 2>/dev/null; then
            ((++fails > 40)) && die "cannot listen on $host:$port"
            sleep 0.05
            continue
        fi
        fails=0
        [[ -n $prev ]] && wait "$prev"
        ((++seq))
        handle "$fd" "$seq" &
        prev=$!
        exec {fd}>&-
    done
}

# Shutdown. A blocking accept(2) restarts after a signal, so a trap in the
# process blocked in accept would only run at the next connection. The loop
# therefore runs in a child (async subshells get default signal actions)
# while this shell waits: `wait` returns as soon as a trapped SIGINT/SIGTERM
# arrives, whether it was sent to this PID alone or to the process group.
trap 'kill "$loop" "$ENGINE_PID" 2>/dev/null; exit 0' TERM INT
serve &
loop=$!
wait "$loop"
status=$?
kill "$ENGINE_PID" 2>/dev/null
exit "$status"
