//go:build ios

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "testing"

func TestLegacyIOSQueueConfig(t *testing.T) {
	savedStaged := QueueStagedSize
	savedOutbound := QueueOutboundSize
	savedInbound := QueueInboundSize
	savedHandshake := QueueHandshakeSize
	savedPreallocated := PreallocatedBuffersPerPool
	t.Cleanup(func() {
		QueueStagedSize = savedStaged
		QueueOutboundSize = savedOutbound
		QueueInboundSize = savedInbound
		QueueHandshakeSize = savedHandshake
		PreallocatedBuffersPerPool = savedPreallocated
	})

	QueueStagedSize = 61
	QueueOutboundSize = 62
	QueueInboundSize = 63
	QueueHandshakeSize = 64
	PreallocatedBuffersPerPool = 65

	c := defaultConfig()
	if c.queueStagedSize != 61 ||
		c.queueOutboundSize != 62 ||
		c.queueInboundSize != 63 ||
		c.queueHandshakeSize != 64 ||
		c.preallocatedBuffersPerPool != 65 {
		t.Fatalf("legacy iOS device config: %+v", c)
	}

	for _, opt := range []Option{
		WithQueueStagedSize(71),
		WithQueueOutboundSize(72),
		WithQueueInboundSize(73),
		WithQueueHandshakeSize(74),
		WithPreallocatedBuffersPerPool(75),
	} {
		opt.apply(&c)
	}
	if c.queueStagedSize != 71 ||
		c.queueOutboundSize != 72 ||
		c.queueInboundSize != 73 ||
		c.queueHandshakeSize != 74 ||
		c.preallocatedBuffersPerPool != 75 {
		t.Fatalf("per-device options did not override legacy iOS config: %+v", c)
	}
}
