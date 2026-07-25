//go:build unix

package server

import (
	"cmp"
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortControl sets SO_REUSEPORT so two proxy generations sharing a
// network namespace can bind the same port while one drains and the other
// takes over.
func reusePortControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	return cmp.Or(err, opErr)
}
