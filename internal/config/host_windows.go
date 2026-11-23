package config

// Windows refuses every VPN interface until it gets its own rules.
var host = rules{goos: "windows"}
