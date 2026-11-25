package main

import (
	"bytes"
	lruList "container/list"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

type rpcFailure struct {
	code    int
	message string
}

func fail(code int, message string) { panic(rpcFailure{code, message}) }
func errorResponse(id any, code int, message string) obj {
	return obj{"jsonrpc": "2.0", "id": id, "error": obj{"code": code, "message": message}}
}

type blockOptions struct {
	slot              uint64
	encoding, details string
	rewards           bool
	maxVersion        int // -1 means absent.
}

func uintLexeme(v any, bits int) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseUint(string(n), 10, bits)
	return value, err == nil
}
func params(v any) blockOptions {
	invalid := func() { fail(-32602, "Invalid getBlock params") }
	p := array(v)
	if len(p) < 1 || len(p) > 2 {
		invalid()
	}
	slot, ok := uintLexeme(p[0], 64)
	if !ok {
		invalid()
	}
	options := blockOptions{slot: slot, encoding: "json", details: "full", rewards: true, maxVersion: -1}
	var config obj
	switch c := item(p, 1).(type) {
	case nil:
		return options
	case string:
		config = obj{"encoding": c}
	case obj:
		config = c
	default:
		invalid()
	}
	readString := func(key string, target *string, allowed ...string) {
		if v := config[key]; v != nil {
			s, ok := v.(string)
			if !ok || !slices.Contains(allowed, s) {
				invalid()
			}
			*target = s
		}
	}
	readString("encoding", &options.encoding, "json", "jsonParsed", "base64", "base58")
	readString("transactionDetails", &options.details, "full", "accounts", "signatures", "none")
	var commitment string
	readString("commitment", &commitment, "finalized", "confirmed")
	if v := config["rewards"]; v != nil {
		options.rewards, ok = v.(bool)
		if !ok {
			invalid()
		}
	}
	if v := config["maxSupportedTransactionVersion"]; v != nil {
		version, valid := uintLexeme(v, 8)
		if !valid {
			invalid()
		}
		options.maxVersion = int(version)
	}
	if options.encoding == "base58" && options.maxVersion >= 1 {
		fail(-32602, "base58 encoding is not supported with maxSupportedTransactionVersion >= 1")
	}
	if options.details == "accounts" && options.encoding != "json" {
		invalid()
	}
	return options
}

type cacheItem[T any] struct {
	slot  uint64
	value T
}
type cache[T any] struct {
	mu    sync.Mutex
	order lruList.List
	items map[uint64]*lruList.Element
}

func (c *cache[T]) get(slot uint64) (value T, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem := c.items[slot]; elem != nil {
		c.order.MoveToFront(elem)
		return elem.Value.(cacheItem[T]).value, true
	}
	return
}
func (c *cache[T]) set(slot uint64, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = make(map[uint64]*lruList.Element)
	}
	item := cacheItem[T]{slot, value}
	if elem := c.items[slot]; elem != nil {
		elem.Value = item
		c.order.MoveToFront(elem)
		return
	}
	c.items[slot] = c.order.PushFront(item)
	if c.order.Len() > 100000 {
		oldest := c.order.Back()
		delete(c.items, oldest.Value.(cacheItem[T]).slot)
		c.order.Remove(oldest)
	}
}

type slotRange struct {
	offset uint64
	length int
}
type archive struct {
	base     *url.URL
	client   *http.Client
	attempts chan struct{}
	ranges   cache[slotRange]
	hashes   cache[string]
}

func retryDelay(value string, retry int) time.Duration {
	if n, err := strconv.ParseUint(value, 10, 64); err == nil {
		return time.Duration(min(n, 10)) * time.Second
	}
	if d, err := http.ParseTime(value); err == nil {
		return min(10*time.Second, max(0, time.Until(d)))
	}
	base := (200 * time.Millisecond) << retry
	return base/2 + rand.N(base/2+1)
}
func (a *archive) rangeAttempt(ctx context.Context, target, interval string, length, cap int) ([]byte, int, string) {
	select {
	case a.attempts <- struct{}{}:
	case <-ctx.Done():
		fail(-32603, "Request canceled")
	}
	defer func() { <-a.attempts }()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		fail(-32603, "Invalid archive request URL")
	}
	req.Header.Set("Range", interval)
	req.Header.Set("User-Agent", "onlyblocks/go")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, 0, ""
	}
	defer resp.Body.Close()
	retryAfter := resp.Header.Get("Retry-After")
	if resp.StatusCode != 206 {
		return nil, resp.StatusCode, retryAfter
	}
	if resp.ContentLength > int64(cap) {
		fail(-32603, "Archive Content-Length exceeds limit")
	}
	// Limit allocation to the expected size, but still consume enough of an
	// oversized stream to distinguish a length mismatch from a transport failure.
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(length)+1))
	if len(body) > cap {
		fail(-32603, "Archive body exceeds limit")
	}
	if err != nil {
		return nil, 0, ""
	}
	if len(body) > length {
		more, err := io.Copy(io.Discard, io.LimitReader(resp.Body, int64(cap+1-len(body))))
		if int64(len(body))+more > int64(cap) {
			fail(-32603, "Archive body exceeds limit")
		}
		if err != nil {
			return nil, 0, ""
		}
	}
	if len(body) != length {
		fail(-32603, "Archive response has incorrect length")
	}
	return body, 206, ""
}
func (a *archive) readRange(ctx context.Context, slot uint64, suffix string, start uint64, length, cap int) []byte {
	need(length > 0 && length <= cap && start <= math.MaxUint64-uint64(length-1), "invalid archive range")
	target := *a.base
	epoch := slot / epochSlots
	tail := fmt.Sprintf("/%d/epoch-%d%s", epoch, epoch, suffix)
	target.Path = strings.TrimRight(target.Path, "/") + tail
	if target.RawPath != "" {
		target.RawPath = strings.TrimRight(target.RawPath, "/") + tail
	}
	interval := fmt.Sprintf("bytes=%d-%d", start, start+uint64(length-1))
	for retry := 0; ; retry++ {
		p, status, after := a.rangeAttempt(ctx, target.String(), interval, length, cap)
		switch {
		case status == 206:
			return p
		case status == 404:
			fail(-32004, fmt.Sprintf("Block not available for slot %d", slot))
		case status != 0 && status != 429 && (status < 500 || status > 599):
			fail(-32603, fmt.Sprintf("Unexpected archive HTTP status %d", status))
		}
		if retry == 4 {
			fail(-32603, "Archive retries exhausted")
		}
		timer := time.NewTimer(retryDelay(after, retry))
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			fail(-32603, "Request canceled")
		}
	}
}
func (a *archive) load(ctx context.Context, slot uint64) car {
	span, ok := a.ranges.get(slot)
	if !ok {
		p := reader{a.readRange(ctx, slot, "-slot-ranges.raw", (slot%epochSlots)*12, 12, 12)}
		span = slotRange{p.u64(), int(p.u32())}
		a.ranges.set(slot, span)
	}
	if span.length == 0 {
		fail(-32007, fmt.Sprintf("Slot %d was skipped", slot))
	}
	return indexCar(a.readRange(ctx, slot, ".car", span.offset, span.length, maxSlice))
}
func (a *archive) blockHash(slot uint64, c car, entries []string) string {
	hash := zeroHash
	if len(entries) > 0 {
		hash = pubkey(bytesOf(item(c.load(entries[len(entries)-1], 1), 2)))
	}
	a.hashes.set(slot, hash)
	return hash
}
func (a *archive) block(ctx context.Context, o blockOptions) obj {
	c := a.load(ctx, o.slot)
	slot, ok := item(c.block, 1).(uint64)
	need(ok && slot == o.slot, "Block slot differs from requested slot")
	entries := links(item(c.block, 3))
	hash := a.blockHash(slot, c, entries)
	header := array(item(c.block, 4))
	parent := num(item(header, 0))
	previous := zeroHash
	if slot != 0 {
		previous, ok = a.hashes.get(parent)
		if !ok {
			p := a.load(ctx, parent)
			_, ok := item(p.block, 1).(uint64)
			need(ok, "Missing parent Block slot")
			previous = a.blockHash(parent, p, links(item(p.block, 3)))
		}
	}
	result := obj{"blockhash": hash, "previousBlockhash": previous, "parentSlot": parent, "blockTime": nil, "blockHeight": nil}
	switch t := item(header, 1).(type) {
	case uint64:
		if t > 0 && t <= math.MaxInt64 {
			result["blockTime"] = t
		}
	case int64:
		result["blockTime"] = t
	}
	if h, ok := item(header, 2).(uint64); ok {
		result["blockHeight"] = h
	}
	if o.details != "none" {
		items := []any{}
		for _, key := range entries {
			entry := c.load(key, 1)
			need(len(bytesOf(item(entry, 2))) == 32, "Invalid entry hash")
			for _, k := range links(item(entry, 3)) {
				n := c.load(k, 0)
				tx := decodeTransaction(c.frame(item(n, 1)))
				if o.details == "signatures" {
					need(len(tx.signatures) > 0, "Missing transaction signature")
					items = append(items, base58(tx.signatures[0]))
				} else {
					var meta obj
					if _, ok := item(n, 2).([]any); ok {
						meta = decodedFrame(slot, c.frame(item(n, 2)), false)
					}
					items = append(items, tx.json(meta, o))
				}
			}
		}
		key := "transactions"
		if o.details == "signatures" {
			key = "signatures"
		}
		result[key] = items
	}
	if o.rewards {
		var p []byte
		if _, ok := item(c.block, 5).([]byte); ok {
			k, absent := link(item(c.block, 5))
			if _, exists := c.index[k]; !absent && exists {
				n := c.load(k, 5)
				if len(n) > 2 {
					p = c.frame(n[2])
				}
			}
		}
		for k, v := range decodedFrame(slot, p, true) {
			result[k] = v
		}
	}
	return result
}
func (a *archive) dispatch(ctx context.Context, raw any) (result obj) {
	var id any
	defer func() {
		if cause := recover(); cause != nil {
			switch e := cause.(type) {
			case rpcFailure:
				result = errorResponse(id, e.code, e.message)
			case decodeError:
				result = errorResponse(id, -32603, string(e))
			default:
				result = errorResponse(id, -32603, "Internal error")
			}
		}
	}()
	request, ok := raw.(obj)
	if !ok {
		fail(-32600, "Invalid Request")
	}
	for _, k := range []string{"jsonrpc", "method"} {
		if v := request[k]; v != nil {
			if _, ok := v.(string); !ok {
				fail(-32600, "Invalid Request")
			}
		}
	}
	switch v := request["id"].(type) {
	case nil, string, json.Number:
		id = v
	default:
		fail(-32600, "Invalid Request")
	}
	method, ok := request["method"].(string)
	if !ok || request["jsonrpc"] != "2.0" {
		fail(-32600, "Invalid Request")
	}
	var value any
	switch method {
	case "getHealth":
		if p := request["params"]; p != nil {
			options, ok := p.([]any)
			if !ok || len(options) != 0 {
				fail(-32602, "Invalid getHealth params")
			}
		}
		value = "ok"
	case "getBlock":
		value = a.block(ctx, params(request["params"]))
	default:
		fail(-32601, "Method not found: "+method)
	}
	return obj{"jsonrpc": "2.0", "result": value, "id": id}
}
func (a *archive) rpc(ctx context.Context, p []byte) any {
	if !utf8.Valid(p) || !json.Valid(p) {
		return errorResponse(nil, -32700, "Parse error")
	}
	d := json.NewDecoder(bytes.NewReader(p))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return errorResponse(nil, -32700, "Parse error")
	}
	if batch, ok := v.([]any); ok {
		if len(batch) == 0 || len(batch) > 100 {
			return errorResponse(nil, -32600, "Invalid Request")
		}
		out := make([]obj, len(batch))
		for i, r := range batch {
			out[i] = a.dispatch(ctx, r)
		}
		return out
	}
	return a.dispatch(ctx, v)
}
func (a *archive) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RequestURI() != "/" {
		w.WriteHeader(404)
		return
	}
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	if r.ContentLength > MiB {
		w.WriteHeader(413)
		return
	}
	p, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MiB))
	if err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			w.WriteHeader(413)
		} else {
			w.WriteHeader(400)
		}
		return
	}
	body, err := json.Marshal(a.rpc(r.Context(), p))
	if err != nil {
		body = []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"Response encoding failed"},"id":null}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Write(body)
}
func environment(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
func main() {
	bind := flag.String("bind", environment("ONLYBLOCKS_BIND", "127.0.0.1:8899"), "listen address")
	base := flag.String("base-url", environment("OLD_FAITHFUL_BASE_URL", "https://files.old-faithful.net"), "Old Faithful archive")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("Unexpected positional arguments")
	}
	target, err := url.Parse(strings.TrimRight(strings.TrimSpace(*base), "/"))
	if err != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") {
		log.Fatal("Invalid archive URL")
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableCompression:  true,
		MaxConnsPerHost:     32,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     30 * time.Second,
	}
	a := &archive{base: target, client: &http.Client{Transport: transport, Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, attempts: make(chan struct{}, 32)}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, err := net.Listen("tcp", *bind)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: a, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	case <-ctx.Done():
		deadline, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if server.Shutdown(deadline) != nil {
			server.Close()
		}
	}
}
