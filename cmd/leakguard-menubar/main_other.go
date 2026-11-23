//go:build !darwin && !linux && !windows

// Command leakguard-menubar is the menu-bar app. Only macOS, Linux and
// Windows are supported yet.
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Stderr))
}

func run(stderr io.Writer) int {
	fmt.Fprintln(stderr, "leakguard-menubar: not supported yet on this system; it runs on macOS, Linux and Windows")
	return 1
}
