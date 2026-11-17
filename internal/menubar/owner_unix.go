//go:build unix

package menubar

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// CheckInstalledCLI checks, without following symlinks, that path is a
// regular executable file owned by root and not writable by group or others,
// and that every directory above it is too. It is read-only, like the check
// enable runs after installing the copy, but it refuses symlinks anywhere on
// the path. A missing file returns an error that wraps fs.ErrNotExist.
func CheckInstalledCLI(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s is not an absolute path", path)
	}
	p := filepath.Clean(path)
	for first := true; ; first = false {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mode := info.Mode()
		switch {
		case mode&os.ModeSymlink != 0:
			return fmt.Errorf("%s is a symlink", p)
		case first && !mode.IsRegular():
			return fmt.Errorf("%s is not a regular file", p)
		case first && mode.Perm()&0o111 == 0:
			return fmt.Errorf("%s is not executable", p)
		case !first && !mode.IsDir():
			return fmt.Errorf("%s is not a directory", p)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot read the owner of " + p)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s is not owned by root", p)
		}
		if mode.Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by non-root users", p)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}
