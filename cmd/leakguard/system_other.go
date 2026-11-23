//go:build !windows

package main

import (
	"os"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

var (
	// systemIsRoot reports whether this process runs as root.
	systemIsRoot = func() bool { return os.Geteuid() == 0 }
	// systemSCM is the Windows Service Control Manager; none here.
	systemSCM daemon.ServiceManager
)

// runAsSystemService runs serve under the Windows Service Control Manager;
// other systems never do, so it reports that it did not run.
func runAsSystemService([]string) (int, bool) { return 0, false }
