package ipc

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"syscall"
	"time"
)

// ErrDaemonUnavailable means nothing listens on the socket: the daemon is not
// installed or not running.
var ErrDaemonUnavailable = errors.New("the leakguard background service is not running")

// ErrNotAuthorized means the daemon refused the peer: it is not root or an
// administrator. Its text is also what the daemon sends.
var ErrNotAuthorized = errors.New("not authorized")

// Client talks to the daemon.
type Client struct {
	// Path is the socket path; empty means DefaultPath.
	Path string
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
	conn, err := net.DialTimeout("unix", path, DialTimeout)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return Status{}, fmt.Errorf("%w (%v)", ErrDaemonUnavailable, err)
		}
		return Status{}, err
	}
	defer conn.Close()
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
