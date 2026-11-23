//go:build windows

package ipc

import (
	"context"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// pipeSDDL protects the daemon's pipe: SYSTEM and Administrators get full
// access, interactive users may only read and write, so an administrator's
// unelevated app can connect; the token check then refuses anyone else.
// P keeps inherited entries out.
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// authorizeAfterRead is true: a pipe client's token can only be read once
// data came through the pipe (ImpersonateNamedPipeClient).
const authorizeAfterRead = true

// listen creates the named pipe s.Path with pipeSDDL. It fails when the pipe
// already exists, such as when another daemon is running: the first instance
// is created exclusively.
func (s *Server) listen() (net.Listener, error) {
	ln, err := winio.ListenPipe(s.Path, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		InputBufferSize:    MaxMessage,
		OutputBufferSize:   MaxMessage,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create %s (is another leakguard daemon running?): %w", s.Path, err)
	}
	return ln, nil
}

// dial connects to the daemon's pipe at the identification impersonation
// level, the least that lets the daemon read the client's token.
func dial(path string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DialTimeout)
	defer cancel()
	return winio.DialPipeAccessImpLevel(ctx, path, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
}
