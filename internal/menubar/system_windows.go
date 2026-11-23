package menubar

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

var (
	modkernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetUserDefaultUILanguage = modkernel32.NewProc("GetUserDefaultUILanguage")
)

// UserLang is the language of the user's Windows display language, with
// the Windows wording (see WindowsLang).
func UserLang() Lang { return WindowsLang(userUILanguage()) }

func userUILanguage() uint16 {
	id, _, _ := procGetUserDefaultUILanguage.Call()
	return uint16(id)
}

// ProgramFiles is the Program Files folder, from the shell's known folder
// rather than an environment variable the user can change; "" when unknown.
func ProgramFiles() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return ""
	}
	return dir
}

// QuerySCM reads services from the Service Control Manager with read
// rights only, so the tray works without administrator rights. It never
// changes a service: every other method fails.
type QuerySCM struct{}

var _ daemon.ServiceManager = QuerySCM{}

var errReadOnly = errors.New("the tray only reads services")

// Query returns the service's state and command line.
func (QuerySCM) Query(name string) (daemon.ServiceInfo, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return daemon.ServiceInfo{}, err
	}
	defer windows.CloseServiceHandle(m)
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return daemon.ServiceInfo{}, err
	}
	s, err := windows.OpenService(m, n, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return daemon.ServiceInfo{}, daemon.ErrServiceNotInstalled
	}
	if err != nil {
		return daemon.ServiceInfo{}, err
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &st); err != nil {
		return daemon.ServiceInfo{}, err
	}
	command, err := serviceCommand(s)
	if err != nil {
		return daemon.ServiceInfo{}, err
	}
	return daemon.ServiceInfo{State: serviceState(st.CurrentState), Command: command}, nil
}

// serviceCommand is the service's binary path name.
func serviceCommand(s windows.Handle) (string, error) {
	size := uint32(1024)
	for tries := 0; tries < 3; tries++ {
		buf := make([]byte, size)
		cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
		err := windows.QueryServiceConfig(s, cfg, size, &size)
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if err != nil {
			return "", err
		}
		return windows.UTF16PtrToString(cfg.BinaryPathName), nil
	}
	return "", errors.New("QueryServiceConfig: the configuration keeps growing")
}

func serviceState(s uint32) daemon.ServiceState {
	switch s {
	case windows.SERVICE_STOPPED:
		return daemon.ServiceStopped
	case windows.SERVICE_START_PENDING:
		return daemon.ServiceStartPending
	case windows.SERVICE_STOP_PENDING:
		return daemon.ServiceStopPending
	}
	return daemon.ServiceRunning
}

func (QuerySCM) Create(string, daemon.ServiceConfig) error { return errReadOnly }
func (QuerySCM) Update(string, daemon.ServiceConfig) error { return errReadOnly }
func (QuerySCM) SetRecovery(string, daemon.Recovery) error { return errReadOnly }
func (QuerySCM) Start(string) error                        { return errReadOnly }
func (QuerySCM) Stop(string) error                         { return errReadOnly }
func (QuerySCM) Delete(string) error                       { return errReadOnly }

// WindowsInstalled reads this computer's leakguard service (see
// WindowsInstalledState) and returns the copy it should run.
func WindowsInstalled() (Install, string) {
	binary := WindowsInstalledCLI(ProgramFiles())
	return WindowsInstalledState(QuerySCM{}, binary), binary
}
