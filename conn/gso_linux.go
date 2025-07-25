//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"golang.org/x/sys/unix"
)

// gsoControlSize returns the recommended buffer size for pooling UDP
// offloading control data.
var gsoControlSize = unix.CmsgSpace(2)
