package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func render(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// S1: the bundle's Info.plist, with the version from the tag.
func TestInfoPlist(t *testing.T) {
	code, out, errOut := render("0.1.0")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	want := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>es</string>
	<key>CFBundleDisplayName</key>
	<string>leakguard</string>
	<key>CFBundleExecutable</key>
	<string>leakguard-menubar</string>
	<key>CFBundleIconFile</key>
	<string>AppIcon</string>
	<key>CFBundleIdentifier</key>
	<string>dev.leakguard.menubar</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>leakguard</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>0.1.0</string>
	<key>CFBundleVersion</key>
	<string>0.1.0</string>
	<key>LSMinimumSystemVersion</key>
	<string>13.0</string>
	<key>LSUIElement</key>
	<true/>
	<key>NSHumanReadableCopyright</key>
	<string>MIT License</string>
</dict>
</plist>
`
	if out != want {
		t.Errorf("Info.plist:\n%s\nwant:\n%s", out, want)
	}
	if runtime.GOOS == "darwin" {
		f := filepath.Join(t.TempDir(), "Info.plist")
		os.WriteFile(f, []byte(out), 0o644)
		if b, err := exec.Command("/usr/bin/plutil", "-lint", f).CombinedOutput(); err != nil {
			t.Errorf("plutil -lint: %v\n%s", err, b)
		}
	}
}

// macOS wants plain numbers in the bundle versions: a pre-release keeps
// only its numbers there (the binaries report the full version).
func TestInfoPlistPrerelease(t *testing.T) {
	code, out, _ := render("0.0.0-ci")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, s := range []string{"<key>CFBundleShortVersionString</key>\n\t<string>0.0.0</string>", "<key>CFBundleVersion</key>\n\t<string>0.0.0</string>"} {
		if !bytes.Contains([]byte(out), []byte(s)) {
			t.Errorf("missing %q in:\n%s", s, out)
		}
	}
}

func TestInfoPlistRejects(t *testing.T) {
	for _, args := range [][]string{{}, {""}, {"v0.1.0"}, {"1.2"}, {"1.2.3.4"}, {"01.2.3"}, {"0.1.0-"}, {"0.1.0; id"}, {"0.1.0</string>"}, {"0.1.0", "extra"}} {
		code, out, errOut := render(args...)
		if code != 2 || out != "" || errOut == "" {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want 2, nothing, a message", args, code, out, errOut)
		}
	}
	_, _, errOut := render("v0.1.0")
	if want := "infoplist: \"v0.1.0\" is not a version like 1.2.3 or 1.2.3-rc.1\nusage: go run ./tools/infoplist VERSION\n"; errOut != want {
		t.Errorf("stderr = %q, want %q", errOut, want)
	}
}
