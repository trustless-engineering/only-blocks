package main

import (
	"bytes"
	"encoding/binary"
	"math/bits"
)

// RFC 8878, with the frame and entropy decoding described in ZSTD_MINI_SPEC.md.
const maxZstdOutput = 512 * MiB
const zstdBlockLimit = 128 * 1024

var LL_BASE = []int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096,
	8192, 16384, 32768, 65536,
}
var LL_BITS = []int{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
	13, 14, 15, 16,
}
var ML_BASE = []int{
	3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
	19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
	35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
	4099, 8195, 16387, 32771, 65539,
}
var ML_BITS = []int{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16,
}
var LL_DEFAULT = []int{
	4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
	-1, -1, -1, -1,
}
var ML_DEFAULT = []int{
	1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
	-1, -1, -1, -1, -1,
}
var OF_DEFAULT = []int{
	1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
}

func bitWindow(data []byte, lo, n int) int {
	if n == 0 {
		return 0
	}
	start := lo / 8
	end := (lo + n + 7) / 8
	var value uint64
	shift := 0
	for i := start; i < end && i < len(data); i++ {
		value |= uint64(data[i]) << shift
		shift += 8
	}
	return int((value >> uint(lo%8)) & ((1 << n) - 1))
}

type reverseBits struct {
	data  []byte
	count int
}

func reverse(data []byte) reverseBits {
	need(len(data) > 0 && data[len(data)-1] != 0, "missing zstd bitstream marker")
	return reverseBits{data, 8*(len(data)-1) + bits.Len8(data[len(data)-1]) - 1}
}
func (r *reverseBits) peek(n int) int {
	if r.count <= 0 || n == 0 {
		return 0
	}
	low := r.count - n
	if low < 0 {
		return bitWindow(r.data, 0, r.count) << (-low)
	}
	return bitWindow(r.data, low, n)
}
func (r *reverseBits) get(n int) int {
	v := r.peek(n)
	r.count -= n
	return v
}

type fseCell struct{ symbol, width, base int }
type fseTable struct {
	cells []fseCell
	width int
}

func makeFSE(probs []int, width int) fseTable {
	size := 1 << width
	table := make([]fseCell, size)
	counters := make([]int, len(probs))
	high := size - 1
	total := 0
	for s, p := range probs {
		if p == -1 {
			table[high].symbol = s
			high--
			p = 1
		}
		counters[s] = p
		total += p
	}
	need(total == size, "invalid FSE distribution")
	step := (size >> 1) + (size >> 3) + 3
	position := 0
	for s, p := range probs {
		for range p {
			table[position].symbol = s
			position = (position + step) & (size - 1)
			for position > high {
				position = (position + step) & (size - 1)
			}
		}
	}
	need(position == 0, "invalid FSE symbol spread")
	for i, cell := range table {
		x := counters[cell.symbol]
		need(x > 0, "missing FSE symbol counter")
		counters[cell.symbol]++
		n := width - bits.Len(uint(x)) + 1
		table[i] = fseCell{cell.symbol, n, (x << n) - size}
	}
	return fseTable{table, width}
}
func readFSE(r *reader, maxSymbol, maxWidth int) fseTable {
	position := 0
	get := func(n int) int { v := bitWindow(r.left, position, n); position += n; return v }
	width := get(4) + 5
	need(width <= maxWidth, "FSE accuracy log too large")
	threshold := 1 << width
	remaining, nbits := threshold+1, width+1
	probs := make([]int, 0, maxSymbol+1)
	for remaining > 1 {
		need(len(probs) <= maxSymbol, "too many FSE symbols")
		biggest := 2*threshold - 1 - remaining
		value := bitWindow(r.left, position, nbits-1)
		if value < biggest {
			position += nbits - 1
		} else {
			value = get(nbits)
			if value >= threshold {
				value -= biggest
			}
		}
		p := value - 1
		probs = append(probs, p)
		if p == -1 {
			remaining--
		} else {
			remaining -= p
		}
		if p == 0 {
			for {
				count := get(2)
				for range count {
					probs = append(probs, 0)
				}
				need(len(probs) <= maxSymbol+1, "too many FSE symbols")
				if count != 3 {
					break
				}
			}
		}
		need(remaining >= 1, "invalid FSE probabilities")
		for remaining < threshold {
			nbits--
			threshold >>= 1
		}
	}
	r.take((position + 7) / 8)
	return makeFSE(probs, width)
}

type huffmanWord struct {
	symbol byte
	width  int
}
type huffman struct {
	cells []huffmanWord
	width int
}

func readHuffman(r *reader) huffman {
	h := int(r.u8())
	weights := make([]int, 0, 256)
	if h >= 128 {
		n := h - 127
		packed := r.take((n + 1) / 2)
		for i := range n {
			b := packed[i/2]
			if i%2 == 0 {
				b >>= 4
			}
			weights = append(weights, int(b&15))
		}
	} else {
		sub := reader{r.take(h)}
		t := readFSE(&sub, 255, 6)
		backward := reverse(sub.left)
		states := [2]int{backward.get(t.width), backward.get(t.width)}
		need(backward.count >= 0, "truncated FSE states")
		for i := 0; ; i = 1 - i {
			need(len(weights) < 255, "too many Huffman weights")
			cell := t.cells[states[i]]
			weights = append(weights, cell.symbol)
			states[i] = cell.base + backward.get(cell.width)
			if backward.count < 0 {
				weights = append(weights, t.cells[states[1-i]].symbol)
				break
			}
		}
	}
	need(len(weights) <= 255, "too many Huffman weights")
	total := 0
	var counts [12]int
	for _, w := range weights {
		need(w <= 11, "invalid Huffman weight")
		if w > 0 {
			total += 1 << (w - 1)
			counts[w]++
		}
	}
	width := bits.Len(uint(total))
	need(width > 0 && width <= 11, "invalid Huffman width")
	remainder := (1 << width) - total
	need(remainder&(remainder-1) == 0, "invalid Huffman remainder")
	w := bits.Len(uint(remainder))
	weights = append(weights, w)
	counts[w]++
	need(counts[1] >= 2 && counts[1]%2 == 0, "invalid Huffman leaf count")
	var starts [12]int
	next := 0
	for w := 1; w <= width; w++ {
		starts[w] = next
		next += counts[w] << (w - 1)
	}
	cells := make([]huffmanWord, 1<<width)
	for symbol, w := range weights {
		if w == 0 {
			continue
		}
		for range 1 << (w - 1) {
			cells[starts[w]] = huffmanWord{byte(symbol), width + 1 - w}
			starts[w]++
		}
	}
	return huffman{cells, width}
}
func (t huffman) stream(data, out []byte) {
	backwards := reverse(data)
	for i := range out {
		cell := t.cells[backwards.peek(t.width)]
		out[i] = cell.symbol
		backwards.count -= cell.width
	}
	need(backwards.count == 0, "invalid Huffman bitstream length")
}

type zstdFrame struct {
	huffman huffman
	seq     [3]fseTable
	rep     [3]int
	history int
	window  uint64
}

func (f *zstdFrame) literals(r *reader) []byte {
	head := int(r.peek())
	typ, format := head&3, (head>>2)&3
	if typ <= 1 {
		width := 1
		shift := 3
		if format == 1 || format == 3 {
			width = 1 + (format+1)/2
			shift = 4
		}
		size := int(r.le(width)) >> shift
		need(size <= zstdBlockLimit, "zstd literals exceed block limit")
		if typ == 0 {
			return r.take(size)
		}
		return bytes.Repeat(r.take(1), size)
	}
	width := [4]int{10, 10, 14, 18}[format]
	packed := int(r.le([4]int{3, 3, 4, 5}[format]))
	size := (packed >> 4) & ((1 << width) - 1)
	compressed := packed >> (4 + width)
	need(size <= zstdBlockLimit, "zstd literals exceed block limit")
	sub := reader{r.take(compressed)}
	if typ == 2 {
		f.huffman = readHuffman(&sub)
	}
	need(f.huffman.cells != nil, "missing previous Huffman table")
	out := make([]byte, size)
	if format == 0 {
		f.huffman.stream(sub.left, out)
		return out
	}
	sizes := [3]int{int(sub.le(2)), int(sub.le(2)), int(sub.le(2))}
	quarter := (size + 3) / 4
	need(size >= 3*quarter, "invalid four-stream literal split")
	for i, n := range sizes {
		f.huffman.stream(sub.take(n), out[i*quarter:(i+1)*quarter])
	}
	f.huffman.stream(sub.left, out[3*quarter:])
	return out
}

var predefined = [3]fseTable{makeFSE(LL_DEFAULT, 6), makeFSE(OF_DEFAULT, 5), makeFSE(ML_DEFAULT, 6)}
var sequenceMaxSymbol = [3]int{35, 31, 52}
var sequenceMaxWidth = [3]int{9, 8, 9}

func (f *zstdFrame) sequenceTable(r *reader, kind, mode int) {
	switch mode {
	case 0:
		f.seq[kind] = predefined[kind]
	case 1:
		symbol := int(r.u8())
		need(symbol <= sequenceMaxSymbol[kind], "invalid RLE sequence symbol")
		f.seq[kind] = fseTable{[]fseCell{{symbol, 0, 0}}, 0}
	case 2:
		f.seq[kind] = readFSE(r, sequenceMaxSymbol[kind], sequenceMaxWidth[kind])
	case 3:
		need(f.seq[kind].cells != nil, "missing previous sequence table")
	}
}
func (f *zstdFrame) offset(encoded, ll int) int {
	if encoded > 3 {
		f.rep = [3]int{encoded - 3, f.rep[0], f.rep[1]}
		return f.rep[0]
	}
	index := encoded - 1
	if ll == 0 {
		index++
	}
	switch index {
	case 1:
		f.rep[0], f.rep[1] = f.rep[1], f.rep[0]
	case 2:
		f.rep = [3]int{f.rep[2], f.rep[0], f.rep[1]}
	case 3:
		f.rep = [3]int{f.rep[0] - 1, f.rep[0], f.rep[1]}
	}
	return f.rep[0]
}
func (f *zstdFrame) compressed(p, out []byte) []byte {
	r := reader{p}
	literals := f.literals(&r)
	size := int(r.u8())
	if size == 0 {
		need(len(r.left) == 0, "trailing empty sequence data")
		need(len(literals) <= maxZstdOutput-len(out) && uint64(len(literals)) <= f.window, "zstd output limit")
		return append(out, literals...)
	}
	if size == 255 {
		size = int(r.le(2)) + 0x7f00
	} else if size >= 128 {
		size = (size-128)*256 + int(r.u8())
	}
	modes := int(r.u8())
	need(modes&3 == 0, "reserved sequence mode bits")
	for k := range 3 {
		f.sequenceTable(&r, k, (modes>>(6-2*k))&3)
	}
	b := reverse(r.left)
	tables := f.seq
	states := [3]int{b.get(tables[0].width), b.get(tables[1].width), b.get(tables[2].width)}
	blockStart := len(out)
	blockLimit := min(zstdBlockLimit, f.window)
	for i := range size {
		ll, of, ml := tables[0].cells[states[0]], tables[1].cells[states[1]], tables[2].cells[states[2]]
		off := (1 << of.symbol) + b.get(of.symbol)
		match := ML_BASE[ml.symbol] + b.get(ML_BITS[ml.symbol])
		literal := LL_BASE[ll.symbol] + b.get(LL_BITS[ll.symbol])
		need(b.count >= 0 && literal <= len(literals), "invalid zstd sequence")
		need(uint64(len(out)-blockStart+literal+match) <= blockLimit && literal+match <= maxZstdOutput-len(out), "zstd output limit")
		out = append(out, literals[:literal]...)
		literals = literals[literal:]
		offset := f.offset(off, literal)
		need(offset > 0 && offset <= len(out)-f.history && uint64(offset) <= f.window, "zstd match offset out of range")
		start := len(out)
		out = append(out, make([]byte, match)...)
		// Each doubled copy reads only bytes that have already been written.
		for copied := 0; copied < match; {
			n := min(offset+copied, match-copied)
			copy(out[start+copied:start+copied+n], out[start-offset:start-offset+n])
			copied += n
		}
		if i+1 < size {
			for _, k := range [3]int{0, 2, 1} {
				cell := tables[k].cells[states[k]]
				states[k] = cell.base + b.get(cell.width)
			}
		}
	}
	need(b.count == 0, "trailing or truncated zstd sequence bits")
	need(uint64(len(out)-blockStart+len(literals)) <= blockLimit && len(literals) <= maxZstdOutput-len(out), "zstd output limit")
	return append(out, literals...)
}

func decompressZstd(data []byte) []byte {
	r := reader{data}
	var out []byte
	for len(r.left) > 0 {
		magic := r.u32()
		if magic&0xfffffff0 == 0x184d2a50 {
			r.sized(uint64(r.u32()))
			continue
		}
		need(magic == 0xfd2fb528, "invalid zstd frame magic")
		flag := r.u8()
		need(flag&8 == 0, "reserved zstd frame bit")
		single := flag&32 != 0
		var window uint64
		if !single {
			descriptor := r.u8()
			base := uint64(1) << (10 + (descriptor >> 3))
			window = base + (base>>3)*uint64(descriptor&7)
		}
		need(r.le([4]int{0, 1, 2, 4}[flag&3]) == 0, "zstd dictionaries unsupported")
		sizeWidth := [4]int{0, 2, 4, 8}[flag>>6]
		if single && sizeWidth == 0 {
			sizeWidth = 1
		}
		size := r.le(sizeWidth)
		if sizeWidth == 2 {
			size += 256
		}
		if single {
			window = size
		}
		need(size <= uint64(maxZstdOutput-len(out)), "zstd content size exceeds limit")
		frame := zstdFrame{rep: [3]int{1, 4, 8}, history: len(out), window: window}
		for {
			header := int(r.le(3))
			length := header >> 3
			need(uint64(length) <= min(zstdBlockLimit, window), "oversize zstd block")
			switch (header >> 1) & 3 {
			case 0:
				need(length <= maxZstdOutput-len(out), "zstd output limit")
				out = append(out, r.take(length)...)
			case 1:
				need(length <= maxZstdOutput-len(out), "zstd output limit")
				out = append(out, bytes.Repeat(r.take(1), length)...)
			case 2:
				out = frame.compressed(r.take(length), out)
			default:
				panic(decodeError("reserved zstd block type"))
			}
			if header&1 != 0 {
				break
			}
		}
		frameData := out[frame.history:]
		need(sizeWidth == 0 || size == uint64(len(frameData)), "zstd frame size mismatch")
		if flag&4 != 0 {
			need(r.u32() == uint32(xxh64(frameData)), "zstd checksum mismatch")
		}
	}
	return out
}
func xxh64(p []byte) uint64 {
	const p1 uint64 = 0x9e3779b185ebca87
	const p2 uint64 = 0xc2b2ae3d27d4eb4f
	const p3 uint64 = 0x165667b19e3779f9
	const p4 uint64 = 0x85ebca77c2b2ae63
	const p5 uint64 = 0x27d4eb2f165667c5
	round := func(acc, lane uint64) uint64 { return bits.RotateLeft64(acc+lane*p2, 31) * p1 }
	hash := p5
	size := len(p)
	if size >= 32 {
		v := [4]uint64{p1, p2, 0, ^p1 + 1}
		v[0] += p2
		for len(p) >= 32 {
			for i := range v {
				v[i] = round(v[i], binary.LittleEndian.Uint64(p[i*8:]))
			}
			p = p[32:]
		}
		hash = bits.RotateLeft64(v[0], 1) + bits.RotateLeft64(v[1], 7) + bits.RotateLeft64(v[2], 12) + bits.RotateLeft64(v[3], 18)
		for _, lane := range v {
			hash = (hash^round(0, lane))*p1 + p4
		}
	}
	hash += uint64(size)
	for len(p) >= 8 {
		hash = bits.RotateLeft64(hash^round(0, binary.LittleEndian.Uint64(p)), 27)*p1 + p4
		p = p[8:]
	}
	if len(p) >= 4 {
		hash = bits.RotateLeft64(hash^(uint64(binary.LittleEndian.Uint32(p))*p1), 23)*p2 + p3
		p = p[4:]
	}
	for _, b := range p {
		hash = bits.RotateLeft64(hash^(uint64(b)*p5), 11) * p1
	}
	hash ^= hash >> 33
	hash *= p2
	hash ^= hash >> 29
	hash *= p3
	return hash ^ (hash >> 32)
}
