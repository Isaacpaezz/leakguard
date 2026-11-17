//go:build unix

package ipc

import (
	"os"
	"sync/atomic"
	"syscall"
	"testing"
)

// The socket must never be reachable by everyone, even before chmod runs.
func TestServerSocketNeverWiderThan0660(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	path := socketPath(t)
	var mode os.FileMode
	chown := func(p string, uid, gid int) error {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mode = info.Mode().Perm()
		return nil
	}
	startServer(t, &Server{Path: path, Handler: statusHandler(new(atomic.Int32)), Authorize: allowAll, Chown: chown})
	if mode&0o007 != 0 {
		t.Fatalf("socket mode before chmod = %v, want no access for others", mode)
	}
}
