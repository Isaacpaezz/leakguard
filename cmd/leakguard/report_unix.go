//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

// linkCount returns the number of hard links of the open file f.
func linkCount(f *os.File) (uint64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("no link count")
	}
	return uint64(st.Nlink), nil
}

// checkReportOwner accepts every owner: only Windows passes --report-file.
func checkReportOwner(string, *os.File) error { return nil }
