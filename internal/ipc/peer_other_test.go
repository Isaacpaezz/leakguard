//go:build !darwin

package ipc

import (
	"net"
	"testing"
)

// S3: without a way to read the peer's credentials, every peer is refused.
func TestAuthorizePeerFailsClosed(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := authorizePeer(a); err == nil {
		t.Fatal("authorizePeer() = nil on a platform without peer credentials")
	}
}
