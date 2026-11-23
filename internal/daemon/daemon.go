// Package daemon installs the background service that runs "leakguard serve"
// (the macOS LaunchDaemon, the Linux systemd unit):
// it loads the firewall rules at boot, verifies them periodically and loads
// them again when OS updates or VPN clients flush them, counts what they
// block, and answers the menu-bar app.
package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
	// LogPath receives the output of every daemon run.
	LogPath = "/Library/Logs/leakguard.log"
	// BootoutWait bounds how long Install waits for launchd to remove the old job.
	BootoutWait = 5 * time.Second
	// pollInterval is how often Install checks whether the old job is gone.
	pollInterval = 100 * time.Millisecond
	// retryDelay is the pause before the single bootstrap retry.
	retryDelay = time.Second
	// logTail bounds how much of the log LastLogLine reads.
	logTail = 4096
)

// Plist renders the LaunchDaemon definition that runs "binary serve" at boot
// and restarts it whenever it exits.
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
		<string>serve</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, Label, binary, LogPath, LogPath)
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

// Manager installs and inspects the background service that runs
// "leakguard serve". Each OS has its own; only package main picks one.
type Manager interface {
	// Install copies the executable at src to a root-owned place and
	// (re)starts the service with it.
	Install(src string) error
	// Uninstall stops the service and removes its files.
	Uninstall() error
	// Installed reports whether the service is installed.
	Installed() bool
	// LegacyInstalled reports whether an older kill switch is installed.
	LegacyInstalled() bool
	// LastLogLine returns the last line the service logged.
	LastLogLine() (string, bool)
}

var _ Manager = Daemon{}

// Daemon installs and removes the LaunchDaemon.
type Daemon struct {
	// Root prefixes every file path; empty means the real file system.
	Root string
	// Launchctl runs launchctl.
	Launchctl Runner
	// Secure makes an installed file root-owned and checks that no normal
	// user can replace it. Nil means SecureRootOwned.
	Secure func(path string) error
	// Sleep waits between launchctl polls. Nil means time.Sleep.
	Sleep func(time.Duration)
}

// LastLogLine returns the last non-empty line of the daemon log, reading only
// its tail. A missing or empty log returns false.
func (d Daemon) LastLogLine() (string, bool) { return lastLogLine(d.path(LogPath)) }

// lastLogLine returns the last non-empty line of the log at path, reading
// only its tail. A missing or empty log returns false.
func lastLogLine(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", false
	}
	off := info.Size() - logTail
	if off < 0 {
		off = 0
	}
	buf := make([]byte, info.Size()-off)
	n, err := f.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false
	}
	text := strings.TrimRight(string(buf[:n]), "\r\n\t ")
	if text == "" {
		return "", false
	}
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		text = text[i+1:]
	}
	return strings.TrimSpace(text), true
}

func (d Daemon) sleep(t time.Duration) {
	if d.Sleep != nil {
		d.Sleep(t)
		return
	}
	time.Sleep(t)
}

// waitUnloaded polls launchd until the job is gone, for at most BootoutWait.
// "launchctl print" fails once launchd no longer knows the job.
func (d Daemon) waitUnloaded() {
	for waited := time.Duration(0); ; waited += pollInterval {
		if _, err := d.Launchctl.Run("print", "system/"+Label); err != nil {
			return
		}
		if waited+pollInterval > BootoutWait {
			return
		}
		d.sleep(pollInterval)
	}
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
	// bootout fails when the daemon is not loaded yet; that is fine. It
	// returns before launchd has removed the job, and bootstrapping while the
	// old job is still there fails ("Bootstrap failed: 5"), so wait for it.
	d.Launchctl.Run("bootout", "system/"+Label)
	d.waitUnloaded()
	if _, err = d.Launchctl.Run("bootstrap", "system", plist); err == nil {
		return nil
	}
	d.sleep(retryDelay)
	d.waitUnloaded()
	if _, err = d.Launchctl.Run("bootstrap", "system", plist); err != nil {
		return fmt.Errorf("the background service is not loaded: %w", err)
	}
	return nil
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
