//go:build windows

package probe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows"
)

// BoundDial connects to addr through iface only, using IP_UNICAST_IF or
// IPV6_UNICAST_IF, so Windows cannot pick the VPN route instead. iface is the
// adapter's alias (its friendly name), as net.Interface names it.
func BoundDial(ctx context.Context, iface string, addr netip.AddrPort) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	network, ipv6 := "tcp4", addr.Addr().Is6()
	if ipv6 {
		network = "tcp6"
	}
	level, opt, value := unicastIfOption(ifi.Index, ipv6)
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), level, opt, value)
		}); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("could not bind the test connection to %s: %w", iface, serr)
		}
		return nil
	}}
	conn, err := d.DialContext(ctx, network, addr.String())
	if err != nil {
		return err
	}
	// The connection succeeded; that alone is the answer.
	conn.Close()
	return nil
}
