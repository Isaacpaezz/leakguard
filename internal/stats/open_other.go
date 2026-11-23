//go:build !windows

package stats

import (
	"os"
	"syscall"
)

// openRead opens path for reading without blocking, even on a FIFO.
func openRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
