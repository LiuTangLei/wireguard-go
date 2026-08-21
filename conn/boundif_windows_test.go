//go:build windows

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

func TestDefaultBindPeekSocketFDWindows(t *testing.T) {
	bind := NewDefaultBind()
	peek, ok := bind.(PeekLookAtSocketFd)
	if !ok {
		t.Fatal("default Windows Bind does not implement PeekLookAtSocketFd")
	}
	if fd, err := peek.PeekLookAtSocketFd4(); fd != -1 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("IPv4 peek before Open = (%d, %v), want (-1, net.ErrClosed)", fd, err)
	}
	if fd, err := peek.PeekLookAtSocketFd6(); fd != -1 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("IPv6 peek before Open = (%d, %v), want (-1, net.ErrClosed)", fd, err)
	}

	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	for name, peekFD := range map[string]func() (int, error){
		"IPv4": peek.PeekLookAtSocketFd4,
		"IPv6": peek.PeekLookAtSocketFd6,
	} {
		if fd, err := peekFD(); err != nil || fd == -1 {
			t.Errorf("%s peek while open = (%d, %v)", name, fd, err)
		}
	}

	var wg sync.WaitGroup
	for _, peekFD := range []func() (int, error){peek.PeekLookAtSocketFd4, peek.PeekLookAtSocketFd6} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				_, _ = peekFD()
			}
		}()
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	if fd, err := peek.PeekLookAtSocketFd4(); fd != -1 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("IPv4 peek after Close = (%d, %v), want (-1, net.ErrClosed)", fd, err)
	}
	if fd, err := peek.PeekLookAtSocketFd6(); fd != -1 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("IPv6 peek after Close = (%d, %v), want (-1, net.ErrClosed)", fd, err)
	}
}
