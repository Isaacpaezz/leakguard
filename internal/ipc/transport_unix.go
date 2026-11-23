//go:build !windows

package ipc

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"runtime"
	"time"
)

// authorizeAfterRead is false: a Unix peer's credentials are known as soon
// as it connects, so it is refused before anything is read from it.
const authorizeAfterRead = false

// dial connects to the daemon's socket.
func dial(path string) (net.Conn, error) {
	return net.DialTimeout("unix", path, DialTimeout)
}

// systemSocketOwner is the socket's owner on this computer.
func systemSocketOwner() socketOwner {
	return socketOwnership(runtime.GOOS, user.LookupGroup)
}

// listen replaces a stale socket, never any other file, and restricts the
// new socket to its owner (see socketOwnership).
func (s *Server) listen() (net.Listener, error) {
	info, err := os.Lstat(s.Path)
	switch {
	case err == nil && info.Mode()&fs.ModeSocket == 0:
		return nil, fmt.Errorf("refusing to replace %s: it is not a socket", s.Path)
	case err == nil:
		// Never take the socket of a daemon that is still running: two
		// daemons would apply rules concurrently, and closing one would
		// unlink the other's socket.
		if conn, err := net.DialTimeout("unix", s.Path, time.Second); err == nil {
			conn.Close()
			return nil, fmt.Errorf("refusing to replace %s: another leakguard daemon is already running", s.Path)
		}
		if err := os.Remove(s.Path); err != nil {
			return nil, err
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	// Create the socket without any access for others, whatever umask the
	// daemon inherited, so it is never reachable by everyone before chmod.
	restore := restrictUmask()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.Path, Net: "unix"})
	restore()
	if err != nil {
		return nil, err
	}
	chown, chmod := s.Chown, s.Chmod
	if chown == nil {
		chown = os.Chown
	}
	if chmod == nil {
		chmod = os.Chmod
	}
	owner := systemSocketOwner
	if s.owner != nil {
		owner = s.owner
	}
	o := owner()
	s.socket = o
	if err := chown(s.Path, 0, o.gid); err != nil {
		ln.Close()
		return nil, fmt.Errorf("could not give %s to root:%s: %w", s.Path, o.group, err)
	}
	if err := chmod(s.Path, o.mode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("could not restrict %s: %w", s.Path, err)
	}
	return ln, nil
}
