//go:build !windows

package wfp

import (
	"fmt"
	"runtime"

	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

// openEngine fails: the Windows Filtering Platform exists only on Windows.
func openEngine() (Engine, error) {
	return nil, fmt.Errorf("the Windows Filtering Platform needs Windows, not %s: %w", runtime.GOOS, firewall.ErrUnsupported)
}

// resolveLUID fails: network adapter aliases exist only on Windows.
func resolveLUID(alias string) (uint64, error) {
	return 0, fmt.Errorf("cannot find network adapter %q: Windows only: %w", alias, firewall.ErrUnsupported)
}
