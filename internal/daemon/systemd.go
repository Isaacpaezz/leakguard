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
	// UnitName is the systemd unit that runs "leakguard serve" on Linux.
	UnitName = "leakguard.service"
	// UnitPath is where the systemd unit lives.
	UnitPath = "/etc/systemd/system/" + UnitName
	// SystemctlPath is the absolute path to systemctl; never resolved
	// through $PATH. /bin is /usr/bin on merged-/usr systems.
	SystemctlPath = "/bin/systemctl"
	// SystemdLogPath receives the output of every daemon run on Linux.
	SystemdLogPath = "/var/log/leakguard.log"
)

// Unit renders the systemd unit that runs "binary serve" at boot, before
// the network comes up, and restarts it whenever it exits. Type=notify
// holds network-pre.target until serve has loaded the rules.
func Unit(binary string) string {
	return fmt.Sprintf(`[Unit]
Description=leakguard: keeps chosen services off the real connection
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=notify
ExecStart=%s serve
Restart=always
StandardOutput=append:%s
StandardError=append:%s

[Install]
WantedBy=multi-user.target
`, binary, SystemdLogPath, SystemdLogPath)
}

// SystemctlRunner runs the real systemctl.
type SystemctlRunner struct{}

// Run implements Runner.
func (SystemctlRunner) Run(args ...string) (string, error) {
	cmd := exec.Command(SystemctlPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

var _ Manager = Systemd{}

// Systemd installs and removes the systemd service on Linux.
type Systemd struct {
	// Root prefixes every file path; empty means the real file system.
	Root string
	// Systemctl runs systemctl.
	Systemctl Runner
	// Secure makes an installed file root-owned and checks that no normal
	// user can replace it. Nil means SecureRootOwned.
	Secure func(path string) error
}

func (d Systemd) path(p string) string { return filepath.Join(d.Root, p) }

// install replaces the logical path p with data. The new file is secured
// as a temporary file next to p and renamed into place only then, so an
// insecure file never replaces the binary or unit the running service
// uses; it is removed instead.
func (d Systemd) install(p string, data []byte, mode os.FileMode) error {
	secure := d.Secure
	if secure == nil {
		secure = SecureRootOwned
	}
	return writeFileChecked(d.path(p), data, mode, func(tmp string) error {
		if err := secure(tmp); err != nil {
			return fmt.Errorf("refusing to install %s: %w", p, err)
		}
		return nil
	})
}

// Install copies the executable at src to BinaryPath, writes the unit,
// enables it and (re)starts it, so a new binary takes effect.
func (d Systemd) Install(src string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := d.install(BinaryPath, data, 0o755); err != nil {
		return err
	}
	if err := d.install(UnitPath, []byte(Unit(BinaryPath)), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", UnitName}} {
		if _, err := d.Systemctl.Run(args...); err != nil {
			return err
		}
	}
	if _, err := d.Systemctl.Run("restart", UnitName); err != nil {
		return fmt.Errorf("the background service is not started: %w", err)
	}
	return nil
}

// Uninstall stops and disables the service and removes its unit and
// binary. systemctl stop fails when the service was never installed; that
// is fine, like a launchctl bootout of a job that is not loaded, but only
// when systemd then says the service does not run. Otherwise Uninstall
// fails and removes nothing, so a running daemon is never orphaned.
func (d Systemd) Uninstall() error {
	if _, err := d.Systemctl.Run("stop", UnitName); err != nil {
		// is-active exits non-zero for every state but active; its output
		// is the state.
		state, _ := d.Systemctl.Run("is-active", UnitName)
		switch strings.TrimSpace(state) {
		case "inactive", "failed", "unknown":
		default:
			return fmt.Errorf("could not stop %s: %w", UnitName, err)
		}
	}
	d.Systemctl.Run("disable", UnitName)
	for _, p := range []string{UnitPath, BinaryPath} {
		if err := os.Remove(d.path(p)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	// Remove the leakguard libexec directory only when it is empty.
	os.Remove(filepath.Dir(d.path(BinaryPath)))
	d.Systemctl.Run("daemon-reload")
	return nil
}

// Installed reports whether the unit exists and runs "leakguard serve".
func (d Systemd) Installed() bool {
	data, err := os.ReadFile(d.path(UnitPath))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "ExecStart="+BinaryPath+" serve" {
			return true
		}
	}
	return false
}

// LegacyInstalled is always false: the old kill switch was macOS only.
func (Systemd) LegacyInstalled() bool { return false }

// LastLogLine returns the last non-empty line of the daemon log.
func (d Systemd) LastLogLine() (string, bool) { return lastLogLine(d.path(SystemdLogPath)) }
