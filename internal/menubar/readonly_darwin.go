package menubar

import "syscall"

// mntReadOnly is MNT_RDONLY from <sys/mount.h>; the syscall package does
// not export it on darwin.
const mntReadOnly = 0x00000001

// ReadOnlyVolume reports whether path is on a read-only volume, such as a
// mounted DMG.
func ReadOnlyVolume(path string) (bool, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false, err
	}
	return st.Flags&mntReadOnly != 0, nil
}
