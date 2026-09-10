package tun

import (
	"bytes"
	"testing"
)

func TestNativeReadAvailableHonorsSmallCallerVector(t *testing.T) {
	d, fd := readAvailableFixture(t)
	all, sizes := availableBuffers()
	buffers, sizes := all[:3], sizes[:3]
	for i := 0; i < 7; i++ {
		pushAvailable(t, fd, availableRecord(bytes.Repeat([]byte{byte(i + 1)}, 64), virtioNetHdr{}))
	}
	seen := 0
	for _, want := range []int{3, 3, 1} {
		n, err := d.Read(buffers, sizes, 8)
		if err != nil || n != want {
			t.Fatalf("bounded vector read = %d, %v; want %d", n, err, want)
		}
		for i := 0; i < n; i++ {
			if sizes[i] != 64 || !bytes.Equal(buffers[i][8:72], bytes.Repeat([]byte{byte(seen + i + 1)}, 64)) {
				t.Fatal("caller vector overflow or record ownership corruption")
			}
		}
		seen += n
	}
}
