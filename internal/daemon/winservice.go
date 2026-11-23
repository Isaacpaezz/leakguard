package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/config"
)

const (
	// ServiceName is the Windows service that runs "leakguard serve".
	ServiceName = "leakguard"
	// ServiceAccount runs the Windows service: LocalSystem, which can
	// change the Windows Filtering Platform.
	ServiceAccount = "LocalSystem"
	// RestartDelay is how long Windows waits before it restarts the
	// service after a failure.
	RestartDelay = 5 * time.Second
	// ResetPeriod is how long without failures resets the failure count.
	ResetPeriod = 24 * time.Hour
	// removeTries bounds how often Uninstall tries to remove a binary the
	// stopped process may still hold for a moment.
	removeTries = 10
	removeDelay = 200 * time.Millisecond
)

// WindowsBinaryPath is the copy the Windows service runs, in
// %ProgramFiles%, which only administrators can write. WindowsLogPath is
// its log, in %ProgramData%\leakguard with the config and the stats.
var WindowsBinaryPath, WindowsLogPath = WindowsPaths(os.Getenv("ProgramFiles"), os.Getenv("ProgramData"))

// ErrServiceNotInstalled is what a ServiceManager returns for a service
// that does not exist.
var ErrServiceNotInstalled = errors.New("the service is not installed")

// WindowsPaths returns the service binary and log paths for the given
// %ProgramFiles% and %ProgramData%; empty means the default.
func WindowsPaths(programFiles, programData string) (binary, log string) {
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	if programData == "" {
		programData = `C:\ProgramData`
	}
	binary = strings.TrimRight(programFiles, `\/`) + `\leakguard\leakguard.exe`
	log = strings.TrimRight(programData, `\/`) + `\leakguard\leakguard.log`
	return binary, log
}

// ServiceCommand is the command line the service runs: binary, always
// quoted (an unquoted path with spaces lets Windows run C:\Program.exe),
// and "serve". Windows paths cannot hold quotes.
func ServiceCommand(binary string) string { return `"` + binary + `" serve` }

// ServiceState is the state of a Windows service.
type ServiceState int

// States of a Windows service; the others count as running.
const (
	ServiceStopped ServiceState = iota
	ServiceStartPending
	ServiceStopPending
	ServiceRunning
)

// ServiceInfo is what the Service Control Manager says about a service.
type ServiceInfo struct {
	State   ServiceState
	Command string // the binary path name, with its arguments
}

// ServiceConfig is how the service is set up.
type ServiceConfig struct {
	DisplayName string
	Command     string // the binary path name, with its arguments
	AutoStart   bool   // starts at boot
	Account     string // the account it runs as
}

// Recovery is what Windows does when the service fails: restart it after
// RestartDelay, every time, and forget the failures after ResetPeriod.
type Recovery struct {
	RestartDelay time.Duration
	ResetPeriod  time.Duration
}

// ServiceManager is the part of the Windows Service Control Manager that
// WindowsService uses. Every method returns ErrServiceNotInstalled for a
// service that does not exist.
type ServiceManager interface {
	Query(name string) (ServiceInfo, error)
	Create(name string, c ServiceConfig) error
	Update(name string, c ServiceConfig) error
	SetRecovery(name string, r Recovery) error
	Start(name string) error
	// Stop asks the service to stop and returns once it has stopped. A
	// stopped service is not an error.
	Stop(name string) error
	Delete(name string) error
}

var _ Manager = WindowsService{}

// WindowsService installs and removes the Windows service.
type WindowsService struct {
	// Binary is where the service's copy of leakguard goes.
	Binary string
	// Command is what the service runs; empty means ServiceCommand(Binary).
	Command string
	// Log is the service's log file.
	Log string
	// SCM is the Service Control Manager.
	SCM ServiceManager
	// Rename replaces a file. Nil means os.Rename.
	Rename func(oldpath, newpath string) error
	// Remove removes a file. Nil means os.Remove.
	Remove func(path string) error
	// Sleep waits between removal tries. Nil means time.Sleep.
	Sleep func(time.Duration)
	// openLog opens the log for LastLogLine. Nil means config.OpenTrusted.
	openLog func(string) (*os.File, error)
}

// NewWindowsService is the service manager of this computer's paths.
func NewWindowsService(scm ServiceManager) WindowsService {
	return WindowsService{Binary: WindowsBinaryPath, Command: ServiceCommand(WindowsBinaryPath), Log: WindowsLogPath, SCM: scm}
}

func (w WindowsService) command() string {
	if w.Command != "" {
		return w.Command
	}
	return ServiceCommand(w.Binary)
}

func (w WindowsService) rename(oldpath, newpath string) error {
	if w.Rename != nil {
		return w.Rename(oldpath, newpath)
	}
	return os.Rename(oldpath, newpath)
}

func (w WindowsService) remove(path string) error {
	if w.Remove != nil {
		return w.Remove(path)
	}
	return os.Remove(path)
}

func (w WindowsService) sleep(d time.Duration) {
	if w.Sleep != nil {
		w.Sleep(d)
		return
	}
	time.Sleep(d)
}

// Install copies the executable at src to Binary, creates or updates the
// service (automatic start, LocalSystem, restart on failure) and
// (re)starts it, so a new binary takes effect. The copy replaces the old
// one atomically; a running service holds its binary, so when the
// replacement fails it is stopped first and the replacement tried again.
// Once Install stopped the service, any later failure starts it again.
func (w WindowsService) Install(src string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	info, err := w.SCM.Query(ServiceName)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrServiceNotInstalled) {
		return fmt.Errorf("cannot query the %s service: %w", ServiceName, err)
	}
	running := exists && info.State != ServiceStopped
	// stopped is set once Install stopped the running service: from then
	// on every failure starts it again, so a failed upgrade never leaves
	// the protection without its daemon.
	stopped := false
	tmp, err := writeTemp(w.Binary, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := w.rename(tmp, w.Binary); err != nil {
		if !running {
			return fmt.Errorf("cannot replace %s: %w", w.Binary, err)
		}
		// A failed stop may still have stopped it.
		stopped, running = true, false
		if serr := w.SCM.Stop(ServiceName); serr != nil {
			return w.startAgain(fmt.Errorf("cannot stop the %s service to replace %s: %w", ServiceName, w.Binary, serr))
		}
		if err := w.rename(tmp, w.Binary); err != nil {
			// The old binary is still there: run it again, so the rules
			// keep being verified.
			return w.startAgain(fmt.Errorf("cannot replace %s: %w", w.Binary, err))
		}
	}
	// A service that exists is updated; Create only runs for a new
	// service, which Install never stopped.
	cfg := ServiceConfig{DisplayName: ServiceName, Command: w.command(), AutoStart: true, Account: ServiceAccount}
	if exists {
		err = w.SCM.Update(ServiceName, cfg)
	} else {
		err = w.SCM.Create(ServiceName, cfg)
	}
	if err != nil {
		return w.startAgainIf(stopped, fmt.Errorf("cannot set up the %s service: %w", ServiceName, err))
	}
	if err := w.SCM.SetRecovery(ServiceName, Recovery{RestartDelay: RestartDelay, ResetPeriod: ResetPeriod}); err != nil {
		return w.startAgainIf(stopped, fmt.Errorf("cannot set the recovery of the %s service: %w", ServiceName, err))
	}
	if running {
		stopped = true
		if err := w.SCM.Stop(ServiceName); err != nil {
			return w.startAgain(fmt.Errorf("the background service is not restarted: %w", err))
		}
	}
	if err := w.SCM.Start(ServiceName); err != nil {
		return w.startAgainIf(stopped, fmt.Errorf("the background service is not started: %w", err))
	}
	return nil
}

// startAgainIf calls startAgain when Install stopped the service.
func (w WindowsService) startAgainIf(stopped bool, err error) error {
	if !stopped {
		return err
	}
	return w.startAgain(err)
}

// startAgain starts the service Install stopped, after err, and reports
// err with whether the service runs again.
func (w WindowsService) startAgain(err error) error {
	if serr := w.SCM.Start(ServiceName); serr != nil {
		return fmt.Errorf("%w; the service could not be started again either: %v", err, serr)
	}
	return fmt.Errorf("%w; the service was started again", err)
}

// writeTemp writes data to a new temporary file next to path and returns
// its name.
func writeTemp(path string, data []byte) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".leakguard-*.exe")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// Uninstall stops and deletes the service and removes its binary. A
// service that is not installed is fine. When the service cannot be
// stopped and still runs, Uninstall fails and removes nothing, so a
// running daemon is never orphaned.
func (w WindowsService) Uninstall() error {
	info, err := w.SCM.Query(ServiceName)
	switch {
	case errors.Is(err, ErrServiceNotInstalled):
	case err != nil:
		return fmt.Errorf("cannot query the %s service: %w", ServiceName, err)
	default:
		if info.State != ServiceStopped {
			if err := w.SCM.Stop(ServiceName); err != nil {
				if now, qerr := w.SCM.Query(ServiceName); qerr != nil || now.State != ServiceStopped {
					return fmt.Errorf("could not stop the %s service: %w", ServiceName, err)
				}
			}
		}
		if err := w.SCM.Delete(ServiceName); err != nil && !errors.Is(err, ErrServiceNotInstalled) {
			return fmt.Errorf("could not delete the %s service: %w", ServiceName, err)
		}
	}
	if err := w.removeBinary(); err != nil {
		return err
	}
	// Remove the leakguard program directory only when it is empty.
	os.Remove(filepath.Dir(w.Binary))
	return nil
}

// removeBinary removes the copy, retrying while the process that just
// stopped may still hold it.
func (w WindowsService) removeBinary() error {
	var err error
	for try := 1; try <= removeTries; try++ {
		if err = w.remove(w.Binary); err == nil || errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if try < removeTries {
			w.sleep(removeDelay)
		}
	}
	return fmt.Errorf("could not remove %s: %w", w.Binary, err)
}

// Installed reports whether the service exists and runs this "serve".
func (w WindowsService) Installed() bool {
	info, err := w.SCM.Query(ServiceName)
	return err == nil && strings.EqualFold(info.Command, w.command())
}

// LegacyInstalled is always false: the old kill switch was macOS only.
func (WindowsService) LegacyInstalled() bool { return false }

// LastLogLine returns the last non-empty line of the service log. On
// Windows a log someone other than SYSTEM and Administrators may write,
// or a link, is not read, so nobody can forge what status shows.
func (w WindowsService) LastLogLine() (string, bool) {
	open := w.openLog
	if open == nil {
		open = config.OpenTrusted
	}
	return lastLine(w.Log, open)
}
