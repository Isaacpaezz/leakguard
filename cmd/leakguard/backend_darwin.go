package main

// The macOS backends: pf and the LaunchDaemon.
var (
	systemFirewall         = pfFirewall
	systemServices         = launchdServices
	systemDefaultInterface = routeDefaultInterface
	systemNotifySocket     = func() string { return "" }
)
