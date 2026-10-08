/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/LiuTangLei/wireguard-go/tun"
	"golang.org/x/crypto/poly1305"
)

const (
	outboundPlaintextHeadroom = MessageEncapsulatingTransportSize + MessageTransportHeaderSize

	outboundPlaintextTailroom = PaddingMultiple - 1 + poly1305.TagSize

	outboundPlaintextSpacing = max(outboundPlaintextHeadroom+outboundPlaintextTailroom, tun.ReadPacketSpacing)

	// singlePacketSlabSize is the size to be used for [packetBuf.slab] when
	// neither [tun.Device] nor [conn.Bind] support batched reads.
	singlePacketSlabSize = MaxContentSize + 2*tun.ReadPacketSpacing

	// batchingSlabSize is the size to be used for [packetBuf.slab] when either
	// [tun.Device] or [conn.Bind] support batched reads. This covers the
	// [tun.GSOSplit] worst case for minimum-sized MTU/MSS, which is documented
	// in [tun.TestGSOSplitMinimumGSOSize].
	batchingSlabSize = 2 * (1<<16 - 1)
)

// The tun package cannot import device, so we assert [tun.ReadPacketSpacing] is
// greater than or equal to [outboundPlaintextSpacing] instead.
const _ = uint(tun.ReadPacketSpacing - outboundPlaintextSpacing)

// packetBuf is a reference counted packet buffer.
type packetBuf struct {
	slab     []byte
	refCount atomic.Int32
	cleanup  func(*packetBuf)
}

// newPacketBuf returns a new [*packetBuf] of the provided size with its
// reference count set to zero. cleanup runs for the returned [*packetBuf] when
// its ref count moves 1->0.
func newPacketBuf(size int, cleanup func(*packetBuf)) *packetBuf {
	return &packetBuf{
		slab:    make([]byte, size),
		cleanup: cleanup,
	}
}

func (p *packetBuf) incRef() {
	p.refCount.Add(1)
}

func (p *packetBuf) decRef() {
	c := p.refCount.Add(-1)
	if c == 0 {
		p.cleanup(p)
	} else if c < 0 {
		panic(fmt.Sprintf("packetBuf.decRef below zero (%d)", c))
	}
}

// AWG expansion must not borrow from the bounded input pool while holding an
// input slab: iOS can have every input buffer queued for encryption at once.
// Separate pools also keep ordinary prefixed MTU packets in small buffers.
var awgSmallBuffers, awgLargeBuffers sync.Pool

func init() {
	awgSmallBuffers.New = func() any { return newPacketBuf(2048, func(p *packetBuf) { awgSmallBuffers.Put(p) }) }
	awgLargeBuffers.New = func() any { return newPacketBuf(MaxMessageSize, func(p *packetBuf) { awgLargeBuffers.Put(p) }) }
}
func getAWGPacketBuf(size int) *packetBuf {
	pool := &awgSmallBuffers
	if size > 2048 {
		pool = &awgLargeBuffers
	}
	p := pool.Get().(*packetBuf)
	p.incRef()
	return p
}
