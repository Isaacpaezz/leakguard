//go:build unix

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// checkRootOwned checks path and all its ancestors.
func checkRootOwned(path string) error {
	p, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot read the owner of %s", p)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s is not owned by root", p)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by non-root users", p)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}
