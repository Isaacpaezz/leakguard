//go:build darwin

package main

import (
	"bytes"
	"os/exec"
	"path/filepath"

	"fyne.io/systray"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/menubar"
)

// language is the language of the Mac's first preferred language.
func language() menubar.Lang {
	out, _ := exec.Command("/usr/bin/defaults", "read", "-g", "AppleLanguages").Output()
	return menubar.ParseLang(string(out))
}

// macPlatform is the macOS menu-bar app: osascript dialogs, template icons,
// the LaunchDaemon plist, the administrator prompt of "do shell script",
// the LaunchAgent login item and the move-to-Applications guard.
type macPlatform struct {
	// exe is this app's executable and home the user's home folder.
	exe, home string
}

func newPlatform(exe, home string) platform { return macPlatform{exe: exe, home: home} }

func (macPlatform) dialogs() menubar.Dialogs { return osaDialogs{} }

func (macPlatform) setIcon(state menubar.State) {
	switch state {
	case menubar.StateProtected:
		systray.SetTemplateIcon(iconProtected, iconProtected)
	case menubar.StateNotSetUp:
		systray.SetTemplateIcon(iconNotSetUp, iconNotSetUp)
	default:
		systray.SetTemplateIcon(iconOutline, iconOutline)
	}
}

func (macPlatform) installed() menubar.Install { return menubar.InstalledState("") }

func (macPlatform) setUp(lang menubar.Lang, all []catalog.Service, d menubar.Draft) error {
	cli, err := adminCLI()
	if err != nil {
		return err
	}
	script, err := menubar.SetupScript(cli, d, all, menubar.AdminPrompt(lang))
	if err != nil {
		return err
	}
	_, err = runScript(script)
	return err
}

func (macPlatform) disable(lang menubar.Lang) error {
	cli, err := adminCLI()
	if err != nil {
		return err
	}
	script, err := menubar.DisableScript(cli, menubar.UninstallPrompt(lang))
	if err != nil {
		return err
	}
	_, err = runScript(script)
	return err
}

// loginMenu is the toggle when the app runs from a .app bundle that
// survives a restart, a hint to move it to Applications when it runs from
// the DMG or translocated, nothing for a development build or an unknown
// home folder.
func (p macPlatform) loginMenu() menubar.LoginMenuItem {
	if !filepath.IsAbs(p.home) {
		return menubar.LoginItemHidden
	}
	return menubar.LoginMenu(p.exe, menubar.ReadOnlyVolume)
}

func (p macPlatform) syncLoginItem() (bool, error) {
	return menubar.SyncLoginItem(p.home, p.exe, menubar.ReadOnlyVolume)
}

func (p macPlatform) setOpenAtLogin(on bool) error {
	return menubar.SetOpenAtLogin(p.home, p.exe, on, menubar.ReadOnlyVolume)
}

func (p macPlatform) removeLoginItem() error { return menubar.RemoveLoginItem(p.home) }

func (p macPlatform) loginItemPresent() bool { return menubar.LoginItemPresent(p.home) }

func (p macPlatform) mustMove() bool {
	return menubar.MustMoveToApplications(p.exe, menubar.ReadOnlyVolume)
}

func (p macPlatform) guardMove(lang menubar.Lang) {
	menubar.GuardMoveToApplications(lang, osaDialogs{}, p.exe, menubar.ReadOnlyVolume)
}

// adminCLI is the leakguard command to run as administrator (see
// menubar.FindCLI), with the quarantine mark cleared when it is the one
// inside this app's bundle.
func adminCLI() (string, error) {
	exe := executable()
	cli, err := menubar.FindCLI(exe, menubar.InstalledState(""), isExecutable, menubar.CheckInstalledCLI)
	if err != nil {
		return "", err
	}
	if err := menubar.PrepareCLI(exe, cli, quarantined, clearQuarantine); err != nil {
		return "", err
	}
	return cli, nil
}

// quarantined reports whether path has the quarantine mark. Any failure
// other than "no such attribute" is menubar.ErrQuarantined, explained in
// plain words (see menubar.QuarantineCheck).
func quarantined(path string) (bool, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("/usr/bin/xattr", menubar.ReadQuarantineArgs(path)...)
	cmd.Stderr = &stderr
	err := cmd.Run()
	return menubar.QuarantineCheck(stderr.String(), err)
}

// clearQuarantine removes the quarantine mark from exactly path.
func clearQuarantine(path string) error {
	out, err := exec.Command("/usr/bin/xattr", menubar.ClearQuarantineArgs(path)...).CombinedOutput()
	if err != nil {
		return menubar.ScriptError(string(out), err)
	}
	return nil
}

// osaDialogs draws the wizard with osascript: "display dialog" and "choose
// from list". Cancelling returns menubar.ErrCancelled.
type osaDialogs struct{}

func (osaDialogs) Ask(d menubar.Dialog) (int, error) {
	out, err := runScript(menubar.DialogScript(d))
	if err != nil {
		return 0, err
	}
	return menubar.ParseButton(out, d)
}

func (osaDialogs) Choose(l menubar.List) ([]int, error) {
	out, err := runScript(menubar.ListScript(l))
	if err != nil {
		return nil, err
	}
	return menubar.ParseChoice(out, l)
}

// runScript runs an AppleScript with osascript and returns what it printed.
func runScript(script string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("/usr/bin/osascript", "-e", script)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", menubar.ScriptError(stderr.String()+stdout.String(), err)
	}
	return stdout.String(), nil
}
