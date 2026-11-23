//go:build linux

package ipc

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// authorizePeer accepts root and members of the socket's administrators
// group (the first of sudo, wheel and admin that existed when the socket
// was created); without such a group, only root.
func authorizePeer(conn net.Conn, owner socketOwner) error {
	cred, err := peerUcred(conn)
	if err != nil {
		return err
	}
	return authorizeLinuxPeer(cred.Uid, cred.Gid, cred.Pid, "/proc", uint32(owner.gid), owner.admins)
}

// peerUcred reads SO_PEERCRED from a Unix socket connection.
func peerUcred(conn net.Conn) (*syscall.Ucred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a Unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, fmt.Errorf("getsockopt SO_PEERCRED: %w", serr)
	}
	return cred, nil
}
