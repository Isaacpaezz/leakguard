package ipc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"time"
)

// Handler runs one checked request and returns its response.
type Handler func(Request) Response

// errNotAuthorized is all an unauthorized peer learns.
const errNotAuthorized = "not authorized"

// Server listens on a Unix socket and answers one request per connection.
type Server struct {
	// Path is the socket path.
	Path string
	// Handler runs every authorized, well-formed request.
	Handler Handler
	// Authorize accepts or refuses a peer before anything is read from it.
	// Nil means the platform check: root or group admin on macOS, and
	// nobody elsewhere (fail closed).
	Authorize func(net.Conn) error
	// Chown and Chmod set the socket's owner and mode. Nil means os.Chown
	// and os.Chmod; tests replace Chown so they run without root.
	Chown func(path string, uid, gid int) error
	Chmod func(path string, mode os.FileMode) error

	deadline time.Duration // zero means Deadline; tests shorten it
	ready    func()        // called once the socket accepts connections
}

// Serve creates the socket and answers requests until ctx is cancelled. It
// closes and removes the socket before returning.
func (s *Server) Serve(ctx context.Context) error {
	if s.Path == "" || s.Handler == nil {
		return errors.New("ipc: server needs a path and a handler")
	}
	ln, err := s.listen()
	if err != nil {
		return err
	}
	defer ln.Close() // also removes the socket file

	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	if s.ready != nil {
		s.ready()
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(conn)
		}()
	}
}

// listen replaces a stale socket, never any other file, and restricts the
// new socket to root:admin 0660.
func (s *Server) listen() (*net.UnixListener, error) {
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
	if err := chown(s.Path, 0, AdminGID); err != nil {
		ln.Close()
		return nil, fmt.Errorf("could not give %s to root:admin: %w", s.Path, err)
	}
	if err := chmod(s.Path, 0o660); err != nil {
		ln.Close()
		return nil, fmt.Errorf("could not restrict %s: %w", s.Path, err)
	}
	return ln, nil
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	d := s.deadline
	if d == 0 {
		d = Deadline
	}
	conn.SetDeadline(time.Now().Add(d))
	authorize := s.Authorize
	if authorize == nil {
		authorize = authorizePeer
	}
	if err := authorize(conn); err != nil {
		writeMessage(conn, Response{Error: errNotAuthorized})
		return
	}
	req, err := ReadRequest(conn)
	if err != nil {
		writeMessage(conn, Response{Error: err.Error()})
		return
	}
	resp := s.Handler(req)
	if !resp.OK && resp.Error == "" {
		resp.Error = "request failed"
	}
	writeMessage(conn, resp)
}
