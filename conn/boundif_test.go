/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"net"
	"sync"
	"testing"
)

func TestStdNetBindPeekSocketFD(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	if fd, err := bind.PeekLookAtSocketFd4(); fd != -1 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("IPv4 peek before Open = (%d, %v), want (-1, net.ErrClosed)", fd, err)
	}
	if fd, err := bind.PeekLookAtSocketFd6(); fd != -1 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("IPv6 peek before Open = (%d, %v), want (-1, net.ErrClosed)", fd, err)
	}

	_, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}

	if bind.ipv4 != nil {
		if fd, err := bind.PeekLookAtSocketFd4(); err != nil || fd < 0 {
			t.Errorf("IPv4 peek while open = (%d, %v)", fd, err)
		}
	}
	if bind.ipv6 != nil {
		if fd, err := bind.PeekLookAtSocketFd6(); err != nil || fd < 0 {
			t.Errorf("IPv6 peek while open = (%d, %v)", fd, err)
		}
	}

	var wg sync.WaitGroup
	for _, peek := range []func() (int, error){bind.PeekLookAtSocketFd4, bind.PeekLookAtSocketFd6} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				_, _ = peek()
			}
		}()
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	if fd, err := bind.PeekLookAtSocketFd4(); fd != -1 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("IPv4 peek after Close = (%d, %v), want (-1, net.ErrClosed)", fd, err)
	}
	if fd, err := bind.PeekLookAtSocketFd6(); fd != -1 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("IPv6 peek after Close = (%d, %v), want (-1, net.ErrClosed)", fd, err)
	}
}
