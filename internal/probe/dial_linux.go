//go:build linux

package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// BoundDial connects to addr through iface only, using SO_BINDTODEVICE, so
// the kernel cannot pick the VPN route instead.
func BoundDial(ctx context.Context, iface string, addr netip.AddrPort) error {
	if _, err := net.InterfaceByName(iface); err != nil {
		return err
	}
	network := "tcp4"
	if addr.Addr().Is6() {
		network = "tcp6"
	}
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return bindError(iface, serr)
	}}
	conn, err := d.DialContext(ctx, network, addr.String())
	if err != nil {
		return err
	}
	// The connection succeeded; that alone is the answer.
	conn.Close()
	return nil
}

// bindError explains a refused SO_BINDTODEVICE: kernels before 5.7 allow it
// only to root.
func bindError(iface string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return fmt.Errorf("this system only lets root bind the test connection to %s; run the test with sudo: %w", iface, err)
	}
	return fmt.Errorf("could not bind the test connection to %s: %w", iface, err)
}
