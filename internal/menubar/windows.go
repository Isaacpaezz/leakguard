package menubar

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/daemon"
)

// The Windows tray's logic without Windows calls, so it is tested on every
// system: the language, which CLI runs elevated and with which arguments,
// and how the elevated run ended.

// WindowsCLIName is the CLI's file name next to the Windows tray app.
const WindowsCLIName = "leakguard.exe"

// errorCancelled is ERROR_CANCELLED: the user declined the UAC prompt.
const errorCancelled = syscall.Errno(1223)

// WindowsLang is the language of the Windows display language langID
// (GetUserDefaultUILanguage), with the Windows wording: Spanish when its
// primary language is LANG_SPANISH (0x0A) in any country, English
// otherwise.
func WindowsLang(langID uint16) Lang {
	l := English
	if langID&0x3FF == 0x0A {
		l = Spanish
	}
	return l.ForOS("windows")
}

// FitUTF16 cuts s to at most max UTF-16 units, ending with "…" when it
// was longer, never splitting a character: the notification area's
// tooltip holds 127 units and its terminator.
func FitUTF16(s string, max int) string {
	if len(utf16.Encode([]rune(s))) <= max {
		return s
	}
	n := 1 // the "…"
	var b strings.Builder
	for _, r := range s {
		if n += utf16.RuneLen(r); n > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String() + "…"
}

// WindowsInstalledCLI is the copy the Windows service runs, in the
// Program Files folder programFiles ("" means C:\Program Files).
func WindowsInstalledCLI(programFiles string) string {
	binary, _ := daemon.WindowsPaths(programFiles, "")
	return binary
}

// WindowsInstalledState reads the Windows service through scm, the Windows
// counterpart of InstalledState: no service is InstallNone, the service
// that runs binary with "serve" is InstallCurrent, and anything else
// (another command, a service that cannot be read) is InstallOld, so the
// installed copy is not reused.
func WindowsInstalledState(scm daemon.ServiceManager, binary string) Install {
	_, err := scm.Query(daemon.ServiceName)
	switch {
	case errors.Is(err, daemon.ErrServiceNotInstalled):
		return InstallNone
	case err != nil:
		return InstallOld
	}
	if (daemon.WindowsService{Binary: binary, SCM: scm}).Installed() {
		return InstallCurrent
	}
	return InstallOld
}

// FindWindowsCLI is FindCLI for the Windows tray app exe: installed is the
// copy the service runs, trusted only when inst is InstallCurrent and
// checkInstalled finds it admin-only (see CheckInstalledCLI); otherwise
// leakguard.exe next to the tray app, when isFile finds it.
func FindWindowsCLI(exe string, inst Install, installed string, isFile func(path string) bool, checkInstalled func(path string) error) (string, error) {
	next := ""
	if checkWindowsPath(exe) == nil {
		next = exe[:strings.LastIndexByte(exe, '\\')+1] + WindowsCLIName
	}
	return findCLI(installed, next, inst, isFile, checkInstalled)
}

// checkWindowsPath refuses a path that is not a plain absolute Windows
// path: a drive letter, a backslash, no "." or ".." parts, valid UTF-8,
// and no quotes or control characters (Windows paths cannot hold them, and
// a quote could end the quoted path early).
func checkWindowsPath(p string) error {
	switch {
	case len(p) < 4 || !isDriveLetter(p[0]) || p[1] != ':' || p[2] != '\\':
		return errors.New("needs an absolute path such as C:\\...")
	case !utf8.ValidString(p):
		return errors.New("the path is not valid UTF-8")
	case strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f || r == '"' || r == '/' }):
		return errors.New("the path contains quotes or control characters")
	}
	for _, part := range strings.Split(p[3:], `\`) {
		if part == "" || part == "." || part == ".." {
			return errors.New("the path is not clean")
		}
	}
	return nil
}

func isDriveLetter(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

// checkWindowsCLIPath is checkCLIPath for Windows paths.
func checkWindowsCLIPath(cli string) error {
	if err := checkWindowsPath(cli); err != nil {
		return kindError{ErrUnsafeCLIPath, fmt.Errorf("the leakguard command: %w", err)}
	}
	return nil
}

// reportFileFlag is the CLI's internal flag that names the file where the
// elevated enable or disable writes its final error message.
const reportFileFlag = "--report-file"

// maxElevationReport bounds what the tray reads of a report file, in
// bytes, like the CLI bounds what it writes.
const maxElevationReport = 4096

// WindowsSetupCommand is the argv that runs "cli enable --report-file
// REPORT --vpn ALIAS SERVICE..." once elevated, the Windows counterpart of
// SetupCommand. The alias may hold spaces and any letter; RunElevated
// quotes each argument. cli and the draft are checked like in SetupScript.
// report is the file for the CLI's error message (see RunElevatedWithReport);
// "" or a path that is not a plain absolute Windows path leaves the flag
// out, and only the exit status is known.
func WindowsSetupCommand(cli string, d Draft, all []catalog.Service, report string) ([]string, error) {
	return windowsSetupCommand(cli, d, all, report, config.Config.Validate)
}

// windowsSetupCommand is WindowsSetupCommand with the draft checked by
// validate; tests on other systems pass the Windows alias rules.
func windowsSetupCommand(cli string, d Draft, all []catalog.Service, report string, validate func(config.Config, []catalog.Service) error) ([]string, error) {
	if err := checkWindowsCLIPath(cli); err != nil {
		return nil, err
	}
	if err := validate(config.Config{VPNInterface: d.VPNInterface, Services: d.Services}, all); err != nil {
		return nil, invalidChoice(err)
	}
	argv := append([]string{cli, "enable"}, reportArgs(report)...)
	argv = append(argv, "--vpn", d.VPNInterface)
	return append(argv, d.Services...), nil
}

// WindowsDisableCommand is the argv that runs "cli disable --report-file
// REPORT" once elevated, for the uninstall; report as in
// WindowsSetupCommand.
func WindowsDisableCommand(cli, report string) ([]string, error) {
	if err := checkWindowsCLIPath(cli); err != nil {
		return nil, err
	}
	return append([]string{cli, "disable"}, reportArgs(report)...), nil
}

// reportArgs passes report to the CLI, first, so the CLI reads it before
// any other mistake; nothing for a path that is not plain.
func reportArgs(report string) []string {
	if report == "" || checkWindowsPath(report) != nil {
		return nil
	}
	return []string{reportFileFlag, report}
}

// ReadElevationReport is the message the elevated CLI wrote to the report
// file at path: at most maxElevationReport bytes, valid UTF-8, trimmed.
// A missing or unreadable file, or a folder, is no message.
func ReadElevationReport(path string) string {
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxElevationReport))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(b), "\uFFFD"))
}

// WindowsCommandLine joins args into the parameters of an elevated run,
// each quoted with the rules CommandLineToArgvW and the Go runtime read
// back (the same as syscall.EscapeArg): an argument with a space, a tab
// or a quote is quoted; quotes get a backslash, and so do the backslashes
// right before a quote or the closing quote. It is never a shell string.
func WindowsCommandLine(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = escapeWindowsArg(a)
	}
	return strings.Join(quoted, " ")
}

func escapeWindowsArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, "\"\\ \t") {
		return s
	}
	space := strings.ContainsAny(s, " \t")
	if !strings.ContainsAny(s, `"\`) {
		return `"` + s + `"`
	}
	var b strings.Builder
	if space {
		b.WriteByte('"')
	}
	slashes := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes+1))
			slashes = 0
		default:
			slashes = 0
		}
		b.WriteByte(s[i])
	}
	if space {
		b.WriteString(strings.Repeat(`\`, slashes))
		b.WriteByte('"')
	}
	return b.String()
}

// ElevationError explains how an elevated run ended: launchErr is
// ShellExecuteExW's error, exitCode the process's exit code and report
// what the CLI wrote to the report file. Declining the UAC prompt
// (ERROR_CANCELLED) is ErrCancelled. A failure says the CLI's message,
// or its exit code when it wrote none: its console cannot be read.
func ElevationError(launchErr error, exitCode uint32, report string) error {
	switch {
	case errors.Is(launchErr, errorCancelled):
		return ErrCancelled
	case launchErr != nil:
		return fmt.Errorf("could not start leakguard as administrator: %s", firstLine(launchErr.Error()))
	case exitCode == 0:
		return nil
	}
	if msg := strings.TrimSpace(report); msg != "" {
		return errors.New(msg)
	}
	return fmt.Errorf("leakguard exited with status %d", exitCode)
}
