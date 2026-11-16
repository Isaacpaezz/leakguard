//go:build !darwin

package probe

import (
	"context"
	"net/netip"
)

// BoundDial is only implemented on macOS.
func BoundDial(context.Context, string, netip.AddrPort) error {
	return ErrNotSupported
}
