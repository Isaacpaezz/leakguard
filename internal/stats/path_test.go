package stats

import (
	"runtime"
	"testing"
)

func TestPathPerOS(t *testing.T) {
	cases := []struct{ goos, programData, want string }{
		{"darwin", "", "/Library/Application Support/leakguard/stats.json"},
		{"linux", "", "/var/lib/leakguard/stats.json"},
		{"windows", `D:\Data`, `D:\Data\leakguard\stats.json`},
		{"windows", `D:\Data\`, `D:\Data\leakguard\stats.json`},
		{"windows", "", `C:\ProgramData\leakguard\stats.json`},
	}
	for _, tc := range cases {
		if got := pathFor(tc.goos, tc.programData); got != tc.want {
			t.Errorf("pathFor(%q, %q) = %q, want %q", tc.goos, tc.programData, got, tc.want)
		}
	}
	if runtime.GOOS == "darwin" && DefaultPath != "/Library/Application Support/leakguard/stats.json" {
		t.Errorf("DefaultPath = %q", DefaultPath)
	}
}
