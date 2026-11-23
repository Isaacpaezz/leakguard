//go:build !darwin && !linux && !windows

package probe

import (
	"context"
	"net/netip"
)

// BoundDial is only implemented on macOS, Linux and Windows.
func BoundDial(context.Context, string, netip.AddrPort) error {
	return ErrNotSupported
}
