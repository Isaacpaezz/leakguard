package config

// SimulateMacOS makes the package judge interface names and VPN
// interfaces by the macOS rules, by name alone, until restore is called.
// It exists for the tests of other packages that simulate a Mac on another
// system, such as the CLI's tests on Windows, whose fake interfaces are no
// real adapters. Never call it outside tests, nor while another goroutine
// uses the package.
func SimulateMacOS() (restore func()) {
	old := host
	host = rules{goos: "darwin"}
	return func() { host = old }
}
