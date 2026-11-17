package ipc

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// <sys/un.h>: getsockopt level and option for the peer's credentials.
const (
	solLocal      = 0
	localPeerCred = 1
)

// authorizePeer accepts root and members of group admin.
func authorizePeer(conn net.Conn) error {
	uid, groups, err := peerCredentials(conn)
	if err != nil {
		return err
	}
	if !allowed(uid, groups) {
		return fmt.Errorf("uid %d is not an administrator", uid)
	}
	return nil
}

// peerCredentials reads LOCAL_PEERCRED from a Unix socket connection.
func peerCredentials(conn net.Conn) (uint32, []uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, nil, errors.New("not a Unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, nil, err
	}
	var buf [xucredSize]byte
	size := uint32(len(buf))
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solLocal, localPeerCred,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	}); err != nil {
		return 0, nil, err
	}
	if errno != 0 {
		return 0, nil, fmt.Errorf("getsockopt LOCAL_PEERCRED: %w", errno)
	}
	if size > uint32(len(buf)) {
		return 0, nil, errors.New("peer credentials do not fit")
	}
	return parseXucred(buf[:size])
}
