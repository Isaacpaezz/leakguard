//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"

	"fyne.io/systray"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/menubar"
)

// language follows the desktop session's locale (see menubar.EnvLang) and
// reads the Linux wording.
func language() menubar.Lang { return menubar.EnvLang(os.Getenv).ForOS("linux") }

// linuxPlatform is the Linux tray app: zenity or kdialog dialogs, colored
// icons, the systemd unit, pkexec for the administrator prompt and an XDG
// autostart entry. Linux has no quarantine, translocation or
// move-to-Applications step.
type linuxPlatform struct {
	// exe is this app's executable and configDir the user's XDG config
	// folder ("" when unknown).
	exe, configDir string
}

func newPlatform(exe, home string) platform {
	return linuxPlatform{exe: exe, configDir: menubar.ConfigDir(os.Getenv, home)}
}

func (linuxPlatform) dialogs() menubar.Dialogs {
	return menubar.ToolDialogs{LookPath: exec.LookPath, Run: runTool}
}

func (linuxPlatform) setIcon(state menubar.State) {
	switch state {
	case menubar.StateProtected:
		systray.SetIcon(linuxIconProtected)
	case menubar.StateNotSetUp:
		systray.SetIcon(linuxIconNotSetUp)
	default:
		systray.SetIcon(linuxIconOutline)
	}
}

func (linuxPlatform) installed() menubar.Install { return menubar.SystemdInstalledState("") }

func (linuxPlatform) setUp(_ menubar.Lang, all []catalog.Service, d menubar.Draft) error {
	cli, err := adminCLI()
	if err != nil {
		return err
	}
	argv, err := menubar.SetupCommand(cli, d, all)
	if err != nil {
		return err
	}
	return runAdmin(argv)
}

func (linuxPlatform) disable(menubar.Lang) error {
	cli, err := adminCLI()
	if err != nil {
		return err
	}
	argv, err := menubar.DisableCommand(cli)
	if err != nil {
		return err
	}
	return runAdmin(argv)
}

func (p linuxPlatform) loginMenu() menubar.LoginMenuItem {
	return menubar.AutostartMenu(p.configDir, p.exe)
}

func (p linuxPlatform) syncLoginItem() (bool, error) {
	return menubar.SyncAutostart(p.configDir, p.exe)
}

func (p linuxPlatform) setOpenAtLogin(on bool) error {
	return menubar.SetAutostart(p.configDir, p.exe, on)
}

func (p linuxPlatform) removeLoginItem() error { return menubar.RemoveAutostart(p.configDir) }

func (p linuxPlatform) loginItemPresent() bool { return menubar.AutostartPresent(p.configDir) }

func (linuxPlatform) mustMove() bool { return false }

func (linuxPlatform) guardMove(menubar.Lang) {}

// adminCLI is the leakguard command to run as root (see
// menubar.FindLinuxCLI): the installed copy when the systemd unit runs it,
// otherwise the one next to this app.
func adminCLI() (string, error) {
	return menubar.FindLinuxCLI("", executable(), isExecutable, menubar.CheckInstalledCLI)
}

// runAdmin runs argv, which starts with pkexec, and explains how it ended.
// An empty argv is an error, never a run.
func runAdmin(argv []string) error {
	if len(argv) == 0 {
		return errors.New("no administrator command to run")
	}
	r, err := runTool(argv[0], argv[1:]...)
	if err != nil {
		return err
	}
	return menubar.AdminCommandError(r)
}

// runTool runs path with args, never through a shell, and returns what it
// printed and its exit code.
func runTool(path string, args ...string) (menubar.ToolResult, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(path, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	r := menubar.ToolResult{Stdout: stdout.String(), Stderr: stderr.String()}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.Exited() {
		r.Code = exit.ExitCode()
		return r, nil
	}
	return r, err
}
