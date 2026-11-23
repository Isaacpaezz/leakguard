package main

// The macOS backends: pf and the LaunchDaemon.
var (
	systemFirewall = pfFirewall
	systemServices = launchdServices
)
