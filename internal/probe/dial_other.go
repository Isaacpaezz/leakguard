//go:build !darwin && !linux

package probe

import (
	"context"
	"net/netip"
)

// BoundDial is only implemented on macOS and Linux.
func BoundDial(context.Context, string, netip.AddrPort) error {
	return ErrNotSupported
}
