package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestZstdFrames(t *testing.T) {
	vectors := []struct {
		hex    string
		output []byte
	}{
		{"28b52ffd2000010000", nil},
		{"28b52ffd200a5100006f6e6c79626c6f636b73", []byte("onlyblocks")},
		{"28b52ffd2064230300aa", bytes.Repeat([]byte{0xaa}, 100)},
		{"502a4d180300000001020328b52ffd2000010000", nil},
		{"28b52ffd0068950000606f6e6c79626c6f636b7320210100fe8a17", []byte("onlyblocks onlyblocks onlyblocks!")},
		{"28b52ffd04584d00001861626301007e6e0848c3d30e", bytes.Repeat([]byte("abc"), 8)},
	}
	var frames, expected []byte
	for _, v := range vectors {
		p, err := hex.DecodeString(v.hex)
		if err != nil {
			t.Fatal(err)
		}
		out, failure := attempt(func() []byte { return decompressZstd(p) })
		if failure != "" || !bytes.Equal(out, v.output) {
			t.Fatalf("frame %s: got %x (%s)", v.hex, out, failure)
		}
		frames = append(frames, p...)
		expected = append(expected, v.output...)
	}
	if out := decompressZstd(frames); !bytes.Equal(out, expected) {
		t.Fatalf("combined frames: got %x", out)
	}
	for _, bad := range [][]byte{frames[:len(frames)-1], append(bytes.Clone(frames), 0)} {
		if _, failure := attempt(func() []byte { return decompressZstd(bad) }); failure == "" {
			t.Fatal("accepted malformed frame sequence")
		}
	}
	frames[len(frames)-1] ^= 1
	if _, failure := attempt(func() []byte { return decompressZstd(frames) }); failure == "" {
		t.Fatal("accepted corrupt checksum")
	}
}
