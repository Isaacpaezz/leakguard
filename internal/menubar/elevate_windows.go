package menubar

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modshell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW = modshell32.NewProc("ShellExecuteExW")
)

// ShellExecuteExW's flags (shellapi.h).
const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
)

// shellExecuteInfo is SHELLEXECUTEINFOW. shellapi.h packs it only on
// 32-bit Windows, where every field is 4 bytes anyway, so the natural Go
// layout matches on every architecture.
type shellExecuteInfo struct {
	size          uint32
	mask          uint32
	hwnd          windows.HWND
	verb          *uint16
	file          *uint16
	parameters    *uint16
	directory     *uint16
	show          int32
	instApp       windows.Handle
	idList        uintptr
	class         *uint16
	keyClass      windows.Handle
	hotKey        uint32
	iconOrMonitor windows.Handle
	process       windows.Handle
}

// RunElevated runs argv (an absolute program, then its arguments) once
// with administrator rights: Windows shows the UAC prompt, and RunElevated
// waits for the program and explains how it ended (see ElevationError).
// The arguments are quoted with WindowsCommandLine, never through a shell,
// and the program's console window stays hidden.
func RunElevated(argv []string) error {
	if len(argv) == 0 {
		return errors.New("no administrator command to run")
	}
	if err := checkWindowsCLIPath(argv[0]); err != nil {
		return err
	}
	code, err := runElevated(argv[0], WindowsCommandLine(argv[1:]))
	return ElevationError(err, code, "")
}

// RunElevatedWithReport is RunElevated for the leakguard CLI, whose
// console cannot be read: it creates an empty report file in the user's
// temporary folder, builds the command with its path (see
// WindowsSetupCommand), and a failure says the message the CLI wrote
// there. The file is removed afterwards; without it, build gets "" and
// only the exit status is known.
func RunElevatedWithReport(build func(report string) ([]string, error)) error {
	report := ""
	if f, err := os.CreateTemp("", "leakguard-report-*.txt"); err == nil {
		report = f.Name()
		f.Close()
		defer os.Remove(report)
	}
	argv, err := build(report)
	if err != nil {
		return err
	}
	if len(argv) == 0 {
		return errors.New("no administrator command to run")
	}
	if err := checkWindowsCLIPath(argv[0]); err != nil {
		return err
	}
	code, err := runElevated(argv[0], WindowsCommandLine(argv[1:]))
	return ElevationError(err, code, ReadElevationReport(report))
}

// runElevated starts file with the "runas" verb and params, waits for it
// and returns its exit code. The error is ShellExecuteExW's, such as
// ERROR_CANCELLED when the user declines the prompt.
func runElevated(file, params string) (uint32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// The Shell may use COM; S_FALSE (already initialized) still needs the
	// matching CoUninitialize.
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED|windows.COINIT_DISABLE_OLE1DDE); err == nil || err == syscall.Errno(1) {
		defer windows.CoUninitialize()
	}
	info := shellExecuteInfo{
		mask:       seeMaskNoCloseProcess | seeMaskNoAsync,
		verb:       winText("runas"),
		file:       winText(file),
		parameters: winText(params),
		show:       windows.SW_HIDE,
	}
	info.size = uint32(unsafe.Sizeof(info))
	if ok, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info))); ok == 0 {
		return 0, err
	}
	if info.process == 0 {
		return 0, errors.New("ShellExecuteExW returned no process")
	}
	defer windows.CloseHandle(info.process)
	if _, err := windows.WaitForSingleObject(info.process, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.process, &code); err != nil {
		return 0, err
	}
	return code, nil
}
