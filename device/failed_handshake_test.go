/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net/netip"
	"testing"
)

// TestLazyPeerArmsReapingTimer verifies that a peer lazily created via a
// PeerLookupFunc (which never completes a handshake) still arms its
// zeroKeyMaterial reaping timer in Start(). Without this, such a peer would
// leak goroutines and buffers forever because the expiry timer is otherwise
// only armed on a successful handshake.
//
// This intentionally avoids testing/synctest: the device's autodraining queues
// (device/channels.go) attach GC finalizers to their channels, and a finalizer
// running on the runtime's finalizer goroutine outside a synctest bubble would
// fatally panic ("receive on synctest channel from outside bubble"). A real
// (non-bubble) device exercises the same Start() code path safely.
func TestLazyPeerArmsReapingTimer(t *testing.T) {
	dev := newTestDevice(t)
	dev.SetPeerLookupFunc(func(pk NoisePublicKey) (*NewPeerConfig, bool) {
		ip := netip.AddrFrom4([4]byte{10, pk[0], pk[1], pk[2]})
		return &NewPeerConfig{AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip, 32)}}, true
	})

	var pk NoisePublicKey
	pk[0] = 0x42

	// LookupPeer creates the peer and calls Start(), which arms the reaping
	// timer for a lazy peer that never completes a handshake.
	peer := dev.LookupPeer(pk)
	if peer == nil {
		t.Fatal("LookupPeer returned nil")
	}
	t.Cleanup(func() { dev.RemovePeer(pk) })

	if !peer.timers.zeroKeyMaterial.IsPending() {
		t.Fatal("zeroKeyMaterial not armed; lazy peer would never be reaped")
	}
}
