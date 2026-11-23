package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// Handler runs one checked request and returns its response.
type Handler func(Request) Response

// Server listens on a Unix socket (on Windows, a named pipe) and answers one
// request per connection.
type Server struct {
	// Path is the socket path, or the pipe name on Windows.
	Path string
	// Handler runs every authorized, well-formed request.
	Handler Handler
	// Authorize accepts or refuses a peer before anything is read from it.
	// Nil means the platform check: root or group admin on macOS, root or
	// the socket's administrators group on Linux, SYSTEM or the
	// Administrators group (also without elevation) on Windows, and nobody
	// elsewhere (fail closed).
	Authorize func(net.Conn) error
	// Chown and Chmod set the socket's owner and mode. Nil means os.Chown
	// and os.Chmod; tests replace Chown so they run without root. Windows
	// ignores both: the pipe's security descriptor restricts it.
	Chown func(path string, uid, gid int) error
	Chmod func(path string, mode os.FileMode) error

	owner     func() socketOwner                // nil means systemSocketOwner
	peerCheck func(net.Conn, socketOwner) error // nil means authorizePeer
	deadline  time.Duration                     // zero means Deadline; tests shorten it
	ready     func()                            // called once the socket accepts connections
	readFirst bool                              // read the request before authorizing, as on Windows

	// socket is the owner resolved when the socket was created; the
	// default peer check uses its group.
	socket socketOwner
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
	defer ln.Close() // also removes the socket file on Unix

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

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	d := s.deadline
	if d == 0 {
		d = Deadline
	}
	conn.SetDeadline(time.Now().Add(d))
	authorize := s.Authorize
	if authorize == nil {
		check := s.peerCheck
		if check == nil {
			check = authorizePeer
		}
		authorize = func(c net.Conn) error { return check(c, s.socket) }
	}
	// Windows can only read a pipe client's token once data came through
	// the pipe, so there the request is read first; it never runs, and its
	// errors are never shown, unless the peer is authorized.
	readFirst := s.readFirst || authorizeAfterRead
	var req Request
	var rerr error
	if readFirst {
		req, rerr = ReadRequest(conn)
	}
	if err := authorize(conn); err != nil {
		// ErrNotAuthorized is all an unauthorized peer learns.
		writeMessage(conn, Response{Error: ErrNotAuthorized.Error()})
		return
	}
	if !readFirst {
		req, rerr = ReadRequest(conn)
	}
	if rerr != nil {
		writeMessage(conn, Response{Error: rerr.Error()})
		return
	}
	resp := s.Handler(req)
	if !resp.OK && resp.Error == "" {
		resp.Error = "request failed"
	}
	writeMessage(conn, resp)
}
