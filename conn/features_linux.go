/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"

	"golang.org/x/sys/unix"
)

const (
	// TODO: upstream to x/sys/unix
	socketOptionLevelUDP   = 17
	socketOptionUDPSegment = 103
	socketOptionUDPGRO     = 104
)

func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	err = rc.Control(func(fd uintptr) {
		if _, e := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, socketOptionUDPSegment); e == nil {
			txOffload = true
		}
		if opt, e := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, socketOptionUDPGRO); e == nil {
			rxOffload = opt == 1
			return
		}
		if e := unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, socketOptionUDPGRO, 1); e == nil {
			rxOffload = true
		}
	})
	if err != nil {
		return false, false
	}
	return txOffload, rxOffload
}
