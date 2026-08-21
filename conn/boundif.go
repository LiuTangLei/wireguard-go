/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "net"

var _ PeekLookAtSocketFd = (*StdNetBind)(nil)

func (s *StdNetBind) PeekLookAtSocketFd4() (fd int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ipv4 == nil {
		return -1, net.ErrClosed
	}
	sysconn, err := s.ipv4.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}

func (s *StdNetBind) PeekLookAtSocketFd6() (fd int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ipv6 == nil {
		return -1, net.ErrClosed
	}
	sysconn, err := s.ipv6.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}
