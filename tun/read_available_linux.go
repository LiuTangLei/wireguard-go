package tun

import (
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Match the bounded H3 enqueue vector. These are only records already ready
// on the FD; an empty queue is never waited on after the first record.
const maxReadyReadRecords = 32

// SetReadBatching opts a Linux virtio TUN into bounded ready-record reads.
// Standard WG/AWG callers retain the original behavior unless they explicitly
// enable this before starting their reader. No kernel qdisc or offload setting
// is changed. The same virtio checksum/GSO decoder remains authoritative.
func (tun *NativeTun) SetReadBatching(enabled bool) bool {
	active := enabled && tun.vnetHdr && len(tun.queues) > 0
	for _, q := range tun.queues {
		q.readOpMu.Lock()
		q.readBatching = active && q.rawConn != nil
		active = active && q.readBatching
		q.readOpMu.Unlock()
	}
	return active
}

// readAvailable waits for the FIRST record only, then drains at most 32
// already-ready records in one netpoll read operation. A GSO record following
// smaller records is retained intact for the next Read, where it has the whole
// caller vector available. This avoids overflowing a partly filled vector or
// discarding the tail of an offloaded packet.
// Caller holds readOpMu.
func (q *tunQueue) readAvailable(slab []byte, packets []ReadPacket) (int, error) {
	if len(packets) == 0 || len(slab) < 2*ReadPacketSpacing {
		return 0, errors.New("invalid TUN batch")
	}
	select {
	case err := <-q.tun.errors:
		return 0, err
	default:
	}
	count := 0
	slabOffset := 0
	var readErr error
	err := q.rawConn.Read(func(fd uintptr) bool {
		for count < min(maxReadyReadRecords, len(packets)) {
			n, e := unix.Read(int(fd), q.readBuff[:])
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
			if e := header.decode(q.readBuff[:n]); e != nil {
				readErr = e
				return true
			}
			if count > 0 && (header.gsoType != unix.VIRTIO_NET_HDR_GSO_NONE || n-virtioNetHdrLen+2*ReadPacketSpacing > len(slab)-slabOffset) {
				q.readPendingLen = n
				return true
			}
			added, e := handleVirtioRead(q.readBuff[:n], slab[slabOffset:], packets[count:])
			if e != nil {
				readErr = e
				return true
			}
			for i := count; i < count+added; i++ {
				packets[i].Offset += slabOffset
			}
			count += added
			if added > 0 {
				last := packets[count-1]
				slabOffset = last.Offset + last.Size
			}
			if header.gsoType != unix.VIRTIO_NET_HDR_GSO_NONE {
				return true
			}
		}
		return true
	})
	// syscall.RawConn exposes an internal poller closing error rather than
	// os.ErrClosed. Normalize only a raw poller failure after this device's
	// own Close; preserve unrelated syscall, decoder and deferred errors.
	if err != nil && q.tun.closed.Load() {
		err = os.ErrClosed
	}
	if err == nil {
		err = readErr
	}
	if errors.Is(err, syscall.EBADFD) || errors.Is(err, syscall.EBADF) {
		err = os.ErrClosed
	}
	if count > 0 && err != nil {
		q.readPendingErr = err
		return count, nil
	}
	return count, err
}
