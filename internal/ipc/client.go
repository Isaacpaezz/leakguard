package ipc

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"syscall"
	"time"
)

// ErrDaemonUnavailable means nothing listens on the socket or the pipe: the
// daemon is not installed or not running.
var ErrDaemonUnavailable = errors.New("the leakguard background service is not running")

// ErrNotAuthorized means the daemon refused the peer: it is not root or an
// administrator. Its text is also what the daemon sends.
var ErrNotAuthorized = errors.New("not authorized")

// Client talks to the daemon.
type Client struct {
	// Path is the socket path (the pipe name on Windows); empty means
	// DefaultPath.
	Path string
	// CheckServer accepts or refuses the server right after connecting,
	// before anything is sent. Nil means the platform check: on Windows
	// the pipe must be owned by LocalSystem, as the leakguard service
	// creates it (see authorizeServer); a Unix socket lives in a
	// directory only root may write, so it is accepted. Tests that run
	// their own daemon replace it.
	CheckServer func(net.Conn) error
}

// Status returns the daemon's current status.
func (c Client) Status() (Status, error) {
	return c.do(Request{Cmd: CmdStatus})
}

// Set protects services through vpn and ends a pause. It returns the status
// after the change.
func (c Client) Set(vpn string, services []string) (Status, error) {
	return c.do(Request{Cmd: CmdSet, VPNInterface: vpn, Services: services})
}

// Pause removes the rules until the next Set. It returns the status after
// the change.
func (c Client) Pause() (Status, error) {
	return c.do(Request{Cmd: CmdPause})
}

func (c Client) do(req Request) (Status, error) {
	path := c.Path
	if path == "" {
		path = DefaultPath
	}
	conn, err := dial(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return Status{}, fmt.Errorf("%w (%v)", ErrDaemonUnavailable, err)
		}
		return Status{}, err
	}
	defer conn.Close()
	check := c.CheckServer
	if check == nil {
		check = checkServer
	}
	if err := check(conn); err != nil {
		return Status{}, err
	}
	conn.SetDeadline(time.Now().Add(Deadline))
	// The server may answer and hang up before reading the request (an
	// unauthorized peer), so a failed write still reads the answer.
	werr := writeMessage(conn, req)
	resp, err := readResponse(conn)
	if err != nil {
		if werr != nil {
			return Status{}, werr
		}
		return Status{}, err
	}
	switch {
	case !resp.OK && resp.Error == ErrNotAuthorized.Error():
		return Status{}, ErrNotAuthorized
	case !resp.OK:
		return Status{}, errors.New(resp.Error)
	}
	return *resp.Status, nil
}
