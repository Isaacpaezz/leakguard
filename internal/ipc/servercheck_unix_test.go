//go:build !windows

package ipc

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
)

// S8 (SF1): a client whose server check fails sends nothing: the request
// (an administrator's set) never reaches the server, and the client
// returns the check's error.
func TestClientRefusesAnUntrustedServerBeforeSending(t *testing.T) {
	path := socketPath(t)
	var calls atomic.Int32
	startServer(t, &Server{Path: path, Handler: statusHandler(&calls), Authorize: allowAll, Chown: (&recorder{}).chown})
	var checked atomic.Int32
	untrusted := Client{Path: path, CheckServer: func(net.Conn) error {
		checked.Add(1)
		return authorizeServer(userSID)
	}}
	if _, err := untrusted.Set("utun4", []string{"anthropic"}); !errors.Is(err, ErrUntrustedServer) {
		t.Fatalf("Set() = %v, want %v", err, ErrUntrustedServer)
	}
	if _, err := untrusted.Status(); !errors.Is(err, ErrUntrustedServer) {
		t.Fatalf("Status() = %v, want %v", err, ErrUntrustedServer)
	}
	if checked.Load() != 2 || calls.Load() != 0 {
		t.Fatalf("checked %d times, handler ran %d times; want 2 and 0", checked.Load(), calls.Load())
	}
	// A Unix socket lives in a directory only root may write: the default
	// check accepts it, as before.
	if st, err := (Client{Path: path}).Status(); err != nil || !st.Protected {
		t.Fatalf("Status() with the default check = %+v, %v", st, err)
	}
}
