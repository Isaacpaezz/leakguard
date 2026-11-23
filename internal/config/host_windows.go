package config

// Windows tells a VPN adapter from the real connection by what
// GetAdaptersAddresses says about it.
var host = rules{goos: "windows", adapters: windowsAdapters}
