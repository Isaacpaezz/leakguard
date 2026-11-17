package ipc

import (
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// isAdmin reports whether this process runs as root or "id -G" lists the
// group admin.
func isAdmin(t *testing.T) bool {
	t.Helper()
	if os.Getuid() == 0 {
		return true
	}
	out, err := exec.Command("/usr/bin/id", "-G").Output()
	if err != nil {
		t.Fatalf("id -G: %v", err)
	}
	return slices.Contains(strings.Fields(string(out)), "80")
}

// The real LOCAL_PEERCRED check, on a connected socket pair.
func TestPeerCredentialsOnDarwin(t *testing.T) {
	path := socketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	uid, groups, err := peerCredentials(server)
	if err != nil {
		t.Fatalf("peerCredentials() = %v", err)
	}
	if int(uid) != os.Getuid() {
		t.Fatalf("peer uid = %d, want %d", uid, os.Getuid())
	}
	if !slices.Contains(groups, uint32(os.Getgid())) {
		t.Fatalf("peer groups %v do not contain the primary group %d", groups, os.Getgid())
	}
	err = authorizePeer(server)
	switch {
	case isAdmin(t):
		if err != nil {
			t.Fatalf("authorizePeer() = %v for an administrator", err)
		}
	default:
		if err == nil {
			t.Fatal("authorizePeer() = nil for a user outside group admin")
		}
	}
}

func TestPeerCredentialsRejectNonUnixConns(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := authorizePeer(a); err == nil {
		t.Fatal("authorizePeer(net.Pipe) = nil")
	}
}

// Without an injected Authorize, the server runs the real check.
func TestServerUsesThePeerCheckByDefault(t *testing.T) {
	path := socketPath(t)
	var calls atomic.Int32
	startServer(t, &Server{Path: path, Handler: statusHandler(&calls), Chown: (&recorder{}).chown})
	_, err := Client{Path: path}.Status()
	if isAdmin(t) {
		if err != nil || calls.Load() != 1 {
			t.Fatalf("Status() as an administrator = %v (handler ran %d times)", err, calls.Load())
		}
		return
	}
	if err == nil || err.Error() != "not authorized" || calls.Load() != 0 {
		t.Fatalf("Status() outside group admin = %v (handler ran %d times)", err, calls.Load())
	}
}
