package main

import (
	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

// The Windows backends: the Windows service; the firewall is not wired yet,
// so every change fails closed with firewall.ErrUnsupported.
var (
	systemFirewall         func(Env) firewall.Firewall
	systemServices         = windowsServices
	systemDefaultInterface = windowsDefaultInterface
	systemNotifySocket     = func() string { return "" }
	systemIsRoot           = processElevated
)

// systemSCM is the real Windows Service Control Manager.
var systemSCM daemon.ServiceManager = daemon.SCM{}
