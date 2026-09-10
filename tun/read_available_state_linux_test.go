package tun

import (
	"errors"
	"os"
	"testing"
)

func TestNativeReadAvailableAfterClose(t *testing.T) {
	d, _ := readAvailableFixture(t)
	buffers, sizes := availableBuffers()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal("repeated Close:", err)
	}
	n, err := d.Read(buffers, sizes, 8)
	if n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("read after close = %d, %v; want os.ErrClosed", n, err)
	}
}

func TestNativeReadAvailablePreservesAsyncError(t *testing.T) {
	d, _ := readAvailableFixture(t)
	buffers, sizes := availableBuffers()
	want := errors.New("test asynchronous TUN error")
	d.errors <- want
	n, err := d.Read(buffers, sizes, 8)
	if n != 0 || err != want {
		t.Fatalf("asynchronous error changed: %d, %v", n, err)
	}
}
