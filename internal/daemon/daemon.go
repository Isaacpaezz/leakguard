// Package daemon installs the macOS LaunchDaemon that re-applies the leakguard
// firewall rules at boot and every minute, because OS updates and VPN clients
// may flush them.
package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// Label identifies the LaunchDaemon.
	Label = "dev.leakguard"
	// PlistPath is where the LaunchDaemon definition lives.
	PlistPath = "/Library/LaunchDaemons/" + Label + ".plist"
	// BinaryPath is the root-owned copy of leakguard that the daemon runs.
	// A root daemon must never run a binary that a normal user can replace.
	BinaryPath = "/usr/local/libexec/leakguard/leakguard"
	// LegacyPlistPath is the LaunchDaemon of the macOS pf prototype.
	LegacyPlistPath = "/Library/LaunchDaemons/com.isaacpaezz.anthropic-killswitch.plist"
	// LaunchctlPath is the absolute path to launchctl; never resolved through $PATH.
	LaunchctlPath = "/bin/launchctl"
	// Interval is how often, in seconds, the daemon re-applies the rules.
	Interval = 60
)

// Plist renders the LaunchDaemon definition that runs "binary apply".
func Plist(binary string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>apply</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StartInterval</key>
	<integer>%d</integer>
</dict>
</plist>
`, Label, binary, Interval)
}

// Runner runs launchctl with the given arguments.
type Runner interface {
	Run(args ...string) (string, error)
}

// ExecRunner runs the real /bin/launchctl.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(args ...string) (string, error) {
	cmd := exec.Command(LaunchctlPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// Daemon installs and removes the LaunchDaemon.
type Daemon struct {
	// Root prefixes every file path; empty means the real file system.
	Root string
	// Launchctl runs launchctl.
	Launchctl Runner
	// Secure makes an installed file root-owned and checks that no normal
	// user can replace it. Nil means SecureRootOwned.
	Secure func(path string) error
}

func (d Daemon) path(p string) string { return filepath.Join(d.Root, p) }

func (d Daemon) secure(path string) error {
	if d.Secure != nil {
		return d.Secure(path)
	}
	return SecureRootOwned(path)
}

// Install copies the executable at src to BinaryPath, writes the plist and
// (re)loads the daemon.
func (d Daemon) Install(src string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	bin := d.path(BinaryPath)
	if err := writeFile(bin, data, 0o755); err != nil {
		return err
	}
	if err := d.secure(bin); err != nil {
		os.Remove(bin)
		return fmt.Errorf("refusing to install %s: %w", BinaryPath, err)
	}
	plist := d.path(PlistPath)
	if err := writeFile(plist, []byte(Plist(BinaryPath)), 0o644); err != nil {
		return err
	}
	if err := d.secure(plist); err != nil {
		os.Remove(plist)
		return fmt.Errorf("refusing to install %s: %w", PlistPath, err)
	}
	// bootout fails when the daemon is not loaded yet; that is fine.
	d.Launchctl.Run("bootout", "system/"+Label)
	_, err = d.Launchctl.Run("bootstrap", "system", plist)
	return err
}

// Uninstall unloads the daemon and removes its plist and binary.
func (d Daemon) Uninstall() error {
	d.Launchctl.Run("bootout", "system/"+Label)
	for _, p := range []string{PlistPath, BinaryPath} {
		if err := os.Remove(d.path(p)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	// Remove the leakguard libexec directory only when it is empty.
	os.Remove(filepath.Dir(d.path(BinaryPath)))
	return nil
}

// Installed reports whether the LaunchDaemon plist exists.
func (d Daemon) Installed() bool {
	_, err := os.Stat(d.path(PlistPath))
	return err == nil
}

// LegacyInstalled reports whether the macOS pf prototype is still installed.
func (d Daemon) LegacyInstalled() bool {
	_, err := os.Stat(d.path(LegacyPlistPath))
	return err == nil
}

// writeFile replaces path atomically with data and the given mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".leakguard-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// SecureRootOwned gives path to root:wheel and checks that path and every
// directory above it are owned by root and not writable by group or others.
func SecureRootOwned(path string) error {
	if err := os.Chown(path, 0, 0); err != nil {
		return err
	}
	return checkRootOwned(path)
}
