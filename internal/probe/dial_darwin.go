//go:build darwin

package probe

import (
	"context"
	"net"
	"net/netip"
	"syscall"
)

// BoundDial connects to addr through iface only, using IP_BOUND_IF or
// IPV6_BOUND_IF, so the kernel cannot pick the VPN route instead.
func BoundDial(ctx context.Context, iface string, addr netip.AddrPort) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	network, level, opt := "tcp4", syscall.IPPROTO_IP, syscall.IP_BOUND_IF
	if addr.Addr().Is6() {
		network, level, opt = "tcp6", syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF
	}
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), level, opt, ifi.Index)
		}); err != nil {
			return err
		}
		return serr
	}}
	conn, err := d.DialContext(ctx, network, addr.String())
	if err != nil {
		return err
	}
	// The connection succeeded; that alone is the answer.
	conn.Close()
	return nil
}
