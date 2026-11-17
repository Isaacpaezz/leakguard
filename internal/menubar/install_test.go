package menubar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

// oldPlist is what enable installed before "serve": a periodic apply.
const oldPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>dev.leakguard</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/libexec/leakguard/leakguard</string>
		<string>apply</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StartInterval</key>
	<integer>60</integer>
</dict>
</plist>
`

func TestInstalledState(t *testing.T) {
	tests := []struct {
		name  string
		plist *string
		want  Install
	}{
		{name: "no plist", want: InstallNone},
		{name: "plist that runs serve", plist: ptrTo(daemon.Plist(daemon.BinaryPath)), want: InstallCurrent},
		{name: "older plist that runs apply", plist: ptrTo(oldPlist), want: InstallOld},
		{
			name:  "serve outside ProgramArguments does not count",
			plist: ptrTo(strings.Replace(oldPlist, "<string>dev.leakguard</string>", "<string>serve</string>", 1)),
			want:  InstallOld,
		},
		{name: "unreadable plist", plist: ptrTo("not a plist"), want: InstallOld},
		{name: "empty plist", plist: ptrTo(""), want: InstallOld},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.plist != nil {
				p := filepath.Join(root, daemon.PlistPath)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(*tc.plist), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := InstalledState(root); got != tc.want {
				t.Errorf("InstalledState = %v, want %v", got, tc.want)
			}
		})
	}
}

func ptrTo(s string) *string { return &s }
