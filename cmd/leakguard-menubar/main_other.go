//go:build !darwin

// Command leakguard-menubar is the menu-bar app. Only macOS is supported yet.
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
	fmt.Fprintln(stderr, "leakguard-menubar: not supported yet on this system; it runs on macOS only")
	return 1
}
