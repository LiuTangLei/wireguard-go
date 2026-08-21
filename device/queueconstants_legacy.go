//go:build !ios

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

// Deprecated: use the corresponding DefaultQueue* constant and a per-device
// WithQueue* option instead.
const (
	QueueStagedSize            = DefaultQueueStagedSize
	QueueOutboundSize          = DefaultQueueOutboundSize
	QueueInboundSize           = DefaultQueueInboundSize
	QueueHandshakeSize         = DefaultQueueHandshakeSize
	PreallocatedBuffersPerPool = DefaultPreallocatedBuffersPerPool
)
