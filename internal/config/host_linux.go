package config

// Linux tells a VPN tunnel from the real connection by the kernel's facts.
var host = rules{goos: "linux", sysfs: "/sys/class/net"}
