# fetch.bash HOST PORT PATH RANGE: one plain-HTTP Range GET over bash's own
# /dev/tcp sockets. The raw HTTP/1.1 response (status line, headers, body) is
# streamed to stdout as od hex, which wire.awk parses; a connect failure
# prints nothing, which wire.awk treats as a retryable transport error.
exec </dev/null
{ exec {s}<>"/dev/tcp/$1/$2"; } 2>/dev/null || exit 0
hosthdr=$1
[[ $hosthdr == *:* ]] && hosthdr="[$hosthdr]"
[[ $2 == 80 ]] || hosthdr+=":$2"
printf 'GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=%s\r\nUser-Agent: onlyblocks/bash-awk\r\nAccept: */*\r\nConnection: close\r\n\r\n' \
    "$3" "$hosthdr" "$4" >&"$s" 2>/dev/null || exit 0
exec "$OB_OD" -An -v -tx1 <&"$s"
