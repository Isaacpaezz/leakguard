//go:build !darwin && !linux

// Command leakguard-menubar is the menu-bar app. Only macOS and Linux are
// supported yet.
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
	fmt.Fprintln(stderr, "leakguard-menubar: not supported yet on this system; it runs on macOS and Linux")
	return 1
}
