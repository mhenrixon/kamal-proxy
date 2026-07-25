//go:build !unix

package server

import (
	"errors"
	"syscall"
)

func reusePortControl(network, address string, c syscall.RawConn) error {
	return errors.New("--reuse-port is not supported on this platform")
}
