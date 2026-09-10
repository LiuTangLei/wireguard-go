package tun

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func readAvailableFixture(t *testing.T) (*NativeTun, int) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(pair[0]), "ready-record-test")
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	device := &NativeTun{tunFile: file, tunRawConn: raw, vnetHdr: true, errors: make(chan error, 1), batchSize: 128}
	t.Cleanup(func() { device.Close(); unix.Close(pair[1]) })
	if !device.SetReadBatching(true) {
		t.Fatal("virtio reader not enabled")
	}
	return device, pair[1]
}
func availableRecord(payload []byte, header virtioNetHdr) []byte {
	b := make([]byte, virtioNetHdrLen+len(payload))
	_ = header.encode(b)
	copy(b[virtioNetHdrLen:], payload)
	return b
}
func pushAvailable(t *testing.T, fd int, record []byte) {
	t.Helper()
	if _, err := unix.Write(fd, record); err != nil {
		t.Fatal(err)
	}
}
func availableBuffers() ([][]byte, []int) {
	b := make([][]byte, 128)
	for i := range b {
		b[i] = make([]byte, 65536+8)
	}
	return b, make([]int, len(b))
}

func TestNativeReadAvailableSmallPacketBoundsAndOwnership(t *testing.T) {
	d, fd := readAvailableFixture(t)
	b, sizes := availableBuffers()
	for i := 0; i < maxReadyReadRecords+4; i++ {
		pushAvailable(t, fd, availableRecord(bytes.Repeat([]byte{byte(i + 1)}, 40), virtioNetHdr{}))
	}
	n, err := d.Read(b, sizes, 8)
	if err != nil || n != maxReadyReadRecords {
		t.Fatalf("first batch=%d %v", n, err)
	}
	for i := 0; i < n; i++ {
		if sizes[i] != 40 || !bytes.Equal(b[i][8:48], bytes.Repeat([]byte{byte(i + 1)}, 40)) || !bytes.Equal(b[i][:8], make([]byte, 8)) {
			t.Fatal("boundary, offset or ownership corrupted")
		}
	}
	n, err = d.Read(b, sizes, 8)
	if err != nil || n != 4 {
		t.Fatalf("second batch=%d %v", n, err)
	}
	for i := 0; i < n; i++ {
		if !bytes.Equal(b[i][8:48], bytes.Repeat([]byte{byte(i + maxReadyReadRecords + 1)}, 40)) {
			t.Fatal("tail records missing")
		}
	}
}
func TestNativeReadAvailableDoesNotWaitToFill(t *testing.T) {
	d, fd := readAvailableFixture(t)
	b, sizes := availableBuffers()
	pushAvailable(t, fd, availableRecord([]byte{1, 2, 3, 4}, virtioNetHdr{}))
	done := make(chan struct{})
	go func() {
		n, err := d.Read(b, sizes, 8)
		if err != nil || n != 1 {
			t.Errorf("single=%d %v", n, err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		d.Close()
		t.Fatal("reader waited to fill batch")
	}
}
func TestNativeReadAvailableRetainsGSOAcrossDisable(t *testing.T) {
	d, fd := readAvailableFixture(t)
	b, sizes := availableBuffers()
	packet := make([]byte, 40+128)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 6
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	copy(packet[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	packet[32] = 0x50
	packet[33] = 0x18
	for i := 40; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	large := availableRecord(packet, virtioNetHdr{gsoType: unix.VIRTIO_NET_HDR_GSO_TCPV4, hdrLen: 40, gsoSize: 32, csumStart: 20, csumOffset: 16})
	first := []byte{9, 8, 7, 6}
	last := []byte{5, 4, 3, 2}
	pushAvailable(t, fd, availableRecord(first, virtioNetHdr{}))
	pushAvailable(t, fd, large)
	pushAvailable(t, fd, availableRecord(last, virtioNetHdr{}))
	n, err := d.Read(b, sizes, 8)
	if err != nil || n != 1 || !bytes.Equal(b[0][8:12], first) {
		t.Fatalf("prefix batch=%d %v", n, err)
	}
	if d.readPendingLen != len(large) {
		t.Fatal("GSO record was not retained")
	}
	d.SetReadBatching(false)
	n, err = d.Read(b, sizes, 8)
	if err != nil || n != 4 {
		t.Fatalf("pending GSO=%d %v", n, err)
	}
	expected, expectedSizes := availableBuffers()
	count, err := handleVirtioRead(bytes.Clone(large), expected, expectedSizes, 8)
	if err != nil || count != n {
		t.Fatal("invalid test GSO")
	}
	for i := 0; i < n; i++ {
		if sizes[i] != expectedSizes[i] || !bytes.Equal(b[i][8:8+sizes[i]], expected[i][8:8+expectedSizes[i]]) {
			t.Fatal("GSO contents changed")
		}
	}
	n, err = d.Read(b, sizes, 8)
	if err != nil || n != 1 || !bytes.Equal(b[0][8:12], last) {
		t.Fatalf("after GSO=%d %v", n, err)
	}
}
func TestNativeReadAvailableDefersErrorAfterGoodRecord(t *testing.T) {
	d, fd := readAvailableFixture(t)
	b, sizes := availableBuffers()
	pushAvailable(t, fd, availableRecord([]byte{1, 2, 3, 4}, virtioNetHdr{}))
	pushAvailable(t, fd, []byte{1})
	n, err := d.Read(b, sizes, 8)
	if n != 1 || err != nil {
		t.Fatalf("valid prefix lost: %d %v", n, err)
	}
	n, err = d.Read(b, sizes, 8)
	if n != 0 || err == nil {
		t.Fatal("malformed record error hidden")
	}
}
