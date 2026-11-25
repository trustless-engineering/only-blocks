package main

import (
	"encoding/binary"
	"fmt"
	"hash/crc64"
	"hash/fnv"
	"math"
	"unicode/utf8"
)

const MiB = 1 << 20
const maxSlice = 128 * MiB
const zeroHash = "11111111111111111111111111111111"

type obj = map[string]any
type decodeError string

func need(ok bool, message string) {
	if !ok {
		panic(decodeError(message))
	}
}

// Capture only expected wire failures when trying an alternate codec.
func attempt[T any](decode func() T) (value T, failure decodeError) {
	defer func() {
		if cause := recover(); cause != nil {
			var expected bool
			if failure, expected = cause.(decodeError); !expected {
				panic(cause)
			}
		}
	}()
	return decode(), ""
}

type reader struct{ left []byte }

func (r *reader) take(n int) []byte {
	need(n >= 0 && n <= len(r.left), "truncated binary value")
	p := r.left[:n]
	r.left = r.left[n:]
	return p
}
func (r *reader) sized(n uint64) []byte {
	need(n <= uint64(len(r.left)), "binary length exceeds input")
	return r.take(int(n))
}
func (r *reader) peek() byte {
	need(len(r.left) != 0, "unexpected end of input")
	return r.left[0]
}
func (r *reader) u8() byte     { return r.take(1)[0] }
func (r *reader) u32() uint32  { return binary.LittleEndian.Uint32(r.take(4)) }
func (r *reader) u64() uint64  { return binary.LittleEndian.Uint64(r.take(8)) }
func (r *reader) f64() float64 { return math.Float64frombits(r.u64()) }
func (r *reader) le(n int) uint64 {
	var v uint64
	for i, b := range r.take(n) {
		v |= uint64(b) << (8 * i)
	}
	return v
}
func (r *reader) varint() uint64 {
	n, width := binary.Uvarint(r.left)
	need(width > 0, "invalid uvarint")
	r.take(width)
	return n
}
func (r *reader) compact() int {
	var value int
	for shift := 0; shift <= 14; shift += 7 {
		b := r.u8()
		need((shift == 0 || b != 0) && (shift < 14 || b <= 3), "invalid compact-u16")
		value |= int(b&127) << shift
		if b < 128 {
			return value
		}
	}
	panic(decodeError("compact-u16 overflow"))
}
func list[T any](r *reader, n uint64, minSize int, next func() T) []T {
	need(n <= uint64(len(r.left)/minSize), "count exceeds input")
	out := make([]T, 0, min(int(n), 256))
	for range n {
		out = append(out, next())
	}
	return out
}

func validText(data []byte) string {
	need(utf8.Valid(data), "invalid UTF-8")
	return string(data)
}

func array(v any) []any { a, _ := v.([]any); return a }
func item(a []any, i int) any {
	if i < len(a) {
		return a[i]
	}
	return nil
}
func bytesOf(v any) []byte { b, _ := v.([]byte); return b }

func cborArg(r *reader, info byte) uint64 {
	if info < 24 {
		return uint64(info)
	}
	need(info <= 27, "reserved CBOR argument")
	var n uint64
	for _, b := range r.take(1 << (info - 24)) {
		n = n<<8 | uint64(b)
	}
	return n
}

type cborMap struct{ version bool }

func cborItem(r *reader, depth int) any {
	need(depth <= 128, "CBOR depth limit")
	head := r.u8()
	major, info := head>>5, head&31
	if major == 7 {
		switch info {
		case 20:
			return false
		case 21:
			return true
		case 22, 23:
			return nil
		case 25, 26, 27:
			cborArg(r, info) // Floats have no numeric accessor in the archive model.
			return nil
		default:
			panic(decodeError("unsupported CBOR simple value"))
		}
	}
	indefinite := info == 31
	var size uint64
	if indefinite {
		need(major >= 2 && major <= 5, "invalid indefinite CBOR item")
	} else {
		size = cborArg(r, info)
	}
	switch major {
	case 0:
		return size
	case 1:
		if size > math.MaxInt64 {
			return nil
		} // Outside the only signed accessor.
		return -1 - int64(size)
	case 6:
		return cborItem(r, depth+1)
	case 2, 3:
		var data []byte
		if !indefinite {
			data = r.sized(size)
		} else {
			for r.peek() != 255 {
				chunk := r.u8()
				need(chunk>>5 == major, "invalid CBOR string chunk")
				p := r.sized(cborArg(r, chunk&31))
				if major == 3 {
					need(utf8.Valid(p), "invalid CBOR text chunk")
				}
				data = append(data, p...)
			}
			r.u8()
		}
		if major == 3 {
			return validText(data)
		}
		return data
	default:
		var entries []any
		var m cborMap
		if !indefinite {
			need(size <= uint64(len(r.left))/(1+uint64(major-4)), "CBOR count exceeds input")
		}
		for i := uint64(0); (!indefinite && i < size) || (indefinite && r.peek() != 255); i++ {
			key := cborItem(r, depth+1)
			if major == 4 {
				entries = append(entries, key)
			} else {
				if name, ok := key.(string); ok && name == "version" {
					m.version = true
				}
				cborItem(r, depth+1)
			}
		}
		if indefinite {
			r.u8()
		}
		if major == 5 {
			return m
		}
		return entries
	}
}

func cbor(data []byte) any {
	r := reader{data}
	v := cborItem(&r, 0)
	need(len(r.left) == 0, "trailing CBOR bytes")
	return v
}

func cid(r *reader) (key string, absent bool) {
	start := r.left
	version, codec := r.varint(), r.varint()
	if version == 0x12 && codec == 0x20 {
		r.take(32)
	} else {
		need(version == 1, "invalid CID version")
		hash, size := r.varint(), r.varint()
		need(size <= 64, "CID digest too long")
		r.sized(size)
		absent = hash == 0 && size == 0
	}
	return string(start[:len(start)-len(r.left)]), absent
}

func link(v any) (string, bool) {
	p := bytesOf(v)
	need(len(p) > 0 && p[0] == 0, "invalid CID link")
	r := reader{p[1:]}
	return cid(&r)
}

func links(v any) []string {
	items := array(v)
	keys := make([]string, 0, len(items))
	for _, entry := range items {
		key, _ := link(entry)
		keys = append(keys, key)
	}
	return keys
}

type car struct {
	index map[string][]byte
	block []any
}

func node(v any, kind uint64) []any {
	a := array(v)
	need(len(a) > 0 && a[0] == kind, fmt.Sprintf("expected IPLD node kind %d", kind))
	return a
}

func indexCar(data []byte) car {
	index := make(map[string][]byte)
	var block []byte
	r := reader{data}
	first := true
	for len(r.left) > 0 {
		size := r.varint()
		if size == 0 {
			continue
		}
		need(size <= 32*MiB, "oversize CAR section")
		section := reader{r.sized(size)}
		header := first && section.peek()>>5 == 5
		first = false
		if header {
			v, failure := attempt(func() any { return cbor(section.left) })
			if m, isMap := v.(cborMap); failure == "" && isMap && m.version {
				continue
			}
		}
		key, _ := cid(&section)
		p := section.left
		index[key] = p
		if len(p) > 0 && p[0]>>5 == 4 {
			info := p[0] & 31
			if info >= 28 && info <= 30 {
				continue
			}
			width := 1
			if info >= 24 && info <= 27 {
				width += 1 << (info - 24)
			}
			if len(p) > width && p[width] == 2 {
				block = p
			}
		}
	}
	need(block != nil, "CAR slice lacks a Block node")
	return car{index, node(cbor(block), 2)}
}
func (c car) load(key string, kind uint64) []any {
	p, ok := c.index[key]
	need(ok, "CID absent from CAR slice")
	return node(cbor(p), kind)
}

var crcISO = crc64.MakeTable(crc64.ISO)

func (c car) frame(v any) []byte {
	root := node(v, 6)
	data := bytesOf(item(root, 4))
	next := links(item(root, 5))
	if len(next) > 0 {
		data = append([]byte(nil), data...)
		seen := make(map[string]bool)
		pending := [][]string{next}
		for len(pending) > 0 {
			top := len(pending) - 1
			if len(pending[top]) == 0 {
				pending = pending[:top]
				continue
			}
			key := pending[top][0]
			pending[top] = pending[top][1:]
			need(!seen[key], "repeated DataFrame CID")
			seen[key] = true
			frame := c.load(key, 6)
			p := bytesOf(item(frame, 4))
			need(len(p) <= maxSlice-len(data), "DataFrame exceeds slice limit")
			data = append(data, p...)
			if next := links(item(frame, 5)); len(next) > 0 {
				pending = append(pending, next)
			}
		}
	}
	if hash, ok := item(root, 1).(uint64); ok && crc64.Checksum(data, crcISO) != hash {
		f := fnv.New64a()
		f.Write(data)
		need(f.Sum64() == hash, "DataFrame hash mismatch")
	}
	return data
}

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58(data []byte) string {
	zeros := 0
	for zeros < len(data) && data[zeros] == 0 {
		zeros++
	}
	digits := make([]byte, 0, len(data))
	for _, b := range data[zeros:] {
		carry := int(b)
		for i, d := range digits {
			carry += int(d) * 256
			digits[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	encoded := make([]byte, zeros+len(digits))
	for i := range zeros {
		encoded[i] = '1'
	}
	for i, d := range digits {
		encoded[len(encoded)-1-i] = b58Alphabet[d]
	}
	return string(encoded)
}
func pubkey(data []byte) string {
	need(len(data) == 32, "invalid public key or hash length")
	return base58(data)
}
