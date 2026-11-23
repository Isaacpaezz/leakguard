package main

import "os"

// The Linux backends: nftables and systemd.
var (
	systemFirewall         = nftFirewall
	systemServices         = systemdServices
	systemDefaultInterface = func() (string, error) { return procDefaultInterface("") }
	systemNotifySocket     = func() string { return os.Getenv("NOTIFY_SOCKET") }
)
