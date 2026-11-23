package main

import (
	"os"

	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

// The Linux backends: systemd now; the nftables firewall comes next, and
// until then every change fails closed with firewall.ErrUnsupported.
var (
	systemFirewall         func(Env) firewall.Firewall
	systemServices         = systemdServices
	systemDefaultInterface = func() (string, error) { return procDefaultInterface("") }
	systemNotifySocket     = func() string { return os.Getenv("NOTIFY_SOCKET") }
)
