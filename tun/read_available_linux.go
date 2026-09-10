package tun

import (
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// SetReadBatching opts a Linux virtio TUN into bounded ready-record reads.
// Standard WG/AWG callers retain the original behavior unless they explicitly
// enable this before starting their reader. No kernel qdisc or offload setting
// is changed. The same virtio checksum/GSO decoder remains authoritative.
func (tun *NativeTun) SetReadBatching(enabled bool) bool {
	tun.readOpMu.Lock()
	defer tun.readOpMu.Unlock()
	tun.readBatching = enabled && tun.vnetHdr && tun.tunRawConn != nil
	return tun.readBatching
}

// readAvailable waits for the FIRST record only, then drains at most sixteen
// already-ready records in one netpoll read operation. A GSO record following
// smaller records is retained intact for the next Read, where it has the whole
// caller vector available. This avoids overflowing a partly filled vector or
// discarding the tail of an offloaded packet.
// Caller holds readOpMu.
func (tun *NativeTun) readAvailable(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || offset < 0 {
		return 0, errors.New("invalid TUN batch")
	}
	select {
	case err := <-tun.errors:
		return 0, err
	default:
	}
	count := 0
	var readErr error
	err := tun.tunRawConn.Read(func(fd uintptr) bool {
		for count < min(16, len(bufs)) {
			n, e := unix.Read(int(fd), tun.readBuff[:])
			if e == unix.EINTR {
				continue
			}
			if e == unix.EAGAIN || e == unix.EWOULDBLOCK {
				return count > 0
			}
			if e != nil {
				readErr = e
				return true
			}
			if n == 0 {
				readErr = io.EOF
				return true
			}
			var header virtioNetHdr
			if e := header.decode(tun.readBuff[:n]); e != nil {
				readErr = e
				return true
			}
			if count > 0 && header.gsoType != unix.VIRTIO_NET_HDR_GSO_NONE {
				tun.readPendingLen = n
				return true
			}
			added, e := handleVirtioRead(tun.readBuff[:n], bufs[count:], sizes[count:], offset)
			if e != nil {
				readErr = e
				return true
			}
			count += added
			if header.gsoType != unix.VIRTIO_NET_HDR_GSO_NONE {
				return true
			}
		}
		return true
	})
	// syscall.RawConn exposes an internal poller closing error rather than
	// os.ErrClosed. Normalize only a raw poller failure after this device's
	// own Close; preserve unrelated syscall, decoder and deferred errors.
	if err != nil && tun.closed.Load() {
		err = os.ErrClosed
	}
	if err == nil {
		err = readErr
	}
	if errors.Is(err, syscall.EBADFD) || errors.Is(err, syscall.EBADF) {
		err = os.ErrClosed
	}
	if count > 0 && err != nil {
		tun.readPendingErr = err
		return count, nil
	}
	return count, err
}
