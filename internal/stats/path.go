package stats

import "strings"

// pathFor is where the daemon keeps the stats on goos. programData is
// %ProgramData% on Windows.
func pathFor(goos, programData string) string {
	switch goos {
	case "linux":
		return "/var/lib/leakguard/stats.json"
	case "windows":
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return strings.TrimRight(programData, `\/`) + `\leakguard\stats.json`
	}
	return "/Library/Application Support/leakguard/stats.json"
}
