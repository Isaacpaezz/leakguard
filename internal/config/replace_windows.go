package config

import (
	"os"
	"path/filepath"
)

// renameBusy reports a replace that another handle keeps out for now.
func renameBusy(err error) bool { return renameBusyOnWindows(err) }

// replaceFile renames tmp over path. os.Root's Rename asks for POSIX
// semantics (FILE_RENAME_POSIX_SEMANTICS), which replace path even while
// readers that share deleting hold it open: they keep reading the old
// file. os.Rename (MoveFileEx) fails with ERROR_ACCESS_DENIED then. A file
// system without POSIX semantics falls back to the classic rename.
func replaceFile(tmp, path string) error {
	dir := filepath.Dir(path)
	if filepath.Dir(tmp) != dir {
		return os.Rename(tmp, path)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Rename(filepath.Base(tmp), filepath.Base(path))
}
