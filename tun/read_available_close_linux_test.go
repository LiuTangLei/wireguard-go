package tun

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestNativeReadAvailableCloseUnblocks(t *testing.T) {
	d, _ := readAvailableFixture(t)
	b, sizes := availableBuffers()
	result := make(chan error, 1)
	go func() { _, err := d.Read(b, sizes, 8); result <- err }()
	time.Sleep(5 * time.Millisecond)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("blocked read close error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing TUN did not unblock ready-record read")
	}
}
func TestNativeReadAvailableOptOutRetainsOneRecordRead(t *testing.T) {
	d, fd := readAvailableFixture(t)
	b, sizes := availableBuffers()
	if d.SetReadBatching(false) {
		t.Fatal("opt-out still enabled")
	}
	for range 3 {
		pushAvailable(t, fd, availableRecord([]byte{1, 2, 3, 4}, virtioNetHdr{}))
	}
	for range 3 {
		n, err := d.Read(b, sizes, 8)
		if n != 1 || err != nil {
			t.Fatalf("ordinary read changed: %d %v", n, err)
		}
	}
}
