//go:build windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// authorizeAfterRead is true: a pipe client's token can only be read once
// data came through the pipe (ImpersonateNamedPipeClient).
const authorizeAfterRead = true

// listen creates the named pipe s.Path with pipeDACL, owned by LocalSystem
// when the daemon runs as the leakguard service (pipeSecurity). It fails
// when the pipe already exists, such as when another daemon is running:
// the first instance is created exclusively.
func (s *Server) listen() (net.Listener, error) {
	user := ""
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		user = u.User.Sid.String()
	}
	ln, err := winio.ListenPipe(s.Path, &winio.PipeConfig{
		SecurityDescriptor: pipeSecurity(user),
		InputBufferSize:    MaxMessage,
		OutputBufferSize:   MaxMessage,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create %s (is another leakguard daemon running?): %w", s.Path, err)
	}
	return ln, nil
}

// dial connects to the daemon's pipe with pipeClientRights at the
// identification impersonation level, the least that lets the daemon read
// the client's token.
func dial(path string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DialTimeout)
	defer cancel()
	return winio.DialPipeAccessImpLevel(ctx, path, pipeClientRights, winio.PipeImpLevelIdentification)
}

// checkServer refuses a pipe that LocalSystem does not own: the leakguard
// service creates its pipe owned by LocalSystem, and nobody else can. The
// owner is read through the client's own handle (READ_CONTROL is part of
// FILE_GENERIC_READ), which works without elevation; the server process's
// token could not be opened by a standard user.
func checkServer(conn net.Conn) error {
	owner, err := pipeOwner(conn)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUntrustedServer, err)
	}
	return authorizeServer(owner)
}

// pipeOwner returns the owner SID of the pipe conn is connected to.
func pipeOwner(conn net.Conn) (string, error) {
	f, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return "", errors.New("not a named pipe connection")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", fmt.Errorf("reading the pipe's owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "", fmt.Errorf("reading the pipe's owner: %v", err)
	}
	return owner.String(), nil
}
