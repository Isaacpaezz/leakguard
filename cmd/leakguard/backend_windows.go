package main

import "github.com/Isaacpaezz/leakguard/internal/daemon"

// The Windows backends: the Windows Filtering Platform and the Windows
// service.
var (
	systemFirewall         = wfpFirewall
	systemServices         = windowsServices
	systemDefaultInterface = windowsDefaultInterface
	systemNotifySocket     = func() string { return "" }
	systemIsRoot           = processElevated
)

// systemSCM is the real Windows Service Control Manager.
var systemSCM daemon.ServiceManager = daemon.SCM{}
