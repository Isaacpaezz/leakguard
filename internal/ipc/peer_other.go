//go:build !darwin && !linux

package ipc

import (
	"errors"
	"net"
)

// authorizePeer refuses every peer: this platform has no peer credential
// check yet, so nobody may talk to the daemon (fail closed).
func authorizePeer(net.Conn, socketOwner) error {
	return errors.New("peer credentials are only checked on macOS and Linux")
}
