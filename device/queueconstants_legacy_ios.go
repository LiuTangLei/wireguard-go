//go:build ios

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

// These variables preserve source and behavior compatibility for iOS clients
// that adjusted queue memory globally before per-device options were added.
// Legacy callers must assign them only during process initialization, before
// any NewDevice call. Deprecated: pass the corresponding WithQueue* option to
// NewDevice instead.
var (
	QueueStagedSize                   = DefaultQueueStagedSize
	QueueOutboundSize                 = DefaultQueueOutboundSize
	QueueInboundSize                  = DefaultQueueInboundSize
	QueueHandshakeSize                = DefaultQueueHandshakeSize
	PreallocatedBuffersPerPool uint32 = DefaultPreallocatedBuffersPerPool
)
