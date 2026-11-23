//go:build !darwin && !linux

package main

import (
	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

// No backend yet: every change fails closed with firewall.ErrUnsupported.
var (
	systemFirewall         func(Env) firewall.Firewall
	systemServices         func(Env) daemon.Manager
	systemDefaultInterface = routeDefaultInterface
	systemNotifySocket     = func() string { return "" }
)
