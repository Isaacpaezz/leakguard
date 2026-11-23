//go:build windows

package main

import (
	"os"

	"fyne.io/systray"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/menubar"
)

// language is the user's Windows display language, with the Windows
// wording.
func language() menubar.Lang { return menubar.UserLang() }

// Windows tray icons: the Linux colored icons, which show on light and dark
// taskbars, as the .ico data LoadImageW reads.
var (
	winIconProtected = mustICO(linuxIconProtected)
	winIconOutline   = mustICO(linuxIconOutline)
	winIconNotSetUp  = mustICO(linuxIconNotSetUp)
)

func mustICO(png []byte) []byte {
	ico, err := icoFromPNG(png)
	if err != nil {
		panic("embedded tray icon: " + err.Error())
	}
	return ico
}

// windowsPlatform is the Windows tray app: TaskDialog or MessageBox
// dialogs, colored icons, the Windows service, the UAC prompt and the
// user's Run key. Windows has no quarantine, translocation or
// move-to-Applications step.
type windowsPlatform struct {
	// exe is this app's executable and appData the user's roaming
	// application data folder ("" when unknown).
	exe, appData string
	lang         menubar.Lang
}

func newPlatform(exe, _ string) platform {
	appData, _ := os.UserConfigDir() // %APPDATA%
	return windowsPlatform{exe: exe, appData: appData, lang: language()}
}

func (p windowsPlatform) dialogs() menubar.Dialogs { return menubar.NewWinDialogs(p.lang) }

func (windowsPlatform) setIcon(state menubar.State) {
	switch state {
	case menubar.StateProtected:
		systray.SetIcon(winIconProtected)
	case menubar.StateNotSetUp:
		systray.SetIcon(winIconNotSetUp)
	default:
		systray.SetIcon(winIconOutline)
	}
}

func (windowsPlatform) installed() menubar.Install {
	inst, _ := menubar.WindowsInstalled()
	return inst
}

func (p windowsPlatform) setUp(_ menubar.Lang, all []catalog.Service, d menubar.Draft) error {
	cli, err := adminCLI(p.exe)
	if err != nil {
		return err
	}
	return menubar.RunElevatedWithReport(func(report string) ([]string, error) {
		return menubar.WindowsSetupCommand(cli, d, all, report)
	})
}

func (p windowsPlatform) disable(menubar.Lang) error {
	cli, err := adminCLI(p.exe)
	if err != nil {
		return err
	}
	return menubar.RunElevatedWithReport(func(report string) ([]string, error) {
		return menubar.WindowsDisableCommand(cli, report)
	})
}

func (p windowsPlatform) loginMenu() menubar.LoginMenuItem {
	return menubar.WindowsLoginMenu(p.appData, p.exe)
}

func (p windowsPlatform) syncLoginItem() (bool, error) {
	return menubar.SyncRunValue(menubar.UserRunKey(), p.appData, p.exe)
}

func (p windowsPlatform) setOpenAtLogin(on bool) error {
	return menubar.SetRunValue(menubar.UserRunKey(), p.appData, p.exe, on)
}

func (p windowsPlatform) removeLoginItem() error {
	return menubar.RemoveRunValue(menubar.UserRunKey(), p.appData)
}

func (p windowsPlatform) loginItemPresent() bool {
	return menubar.RunValuePresent(menubar.UserRunKey(), p.appData)
}

func (windowsPlatform) mustMove() bool { return false }

func (windowsPlatform) guardMove(menubar.Lang) {}

// adminCLI is the leakguard command to run elevated (see
// menubar.FindWindowsCLI): the installed copy when the service runs it and
// it is admin-only, otherwise leakguard.exe next to this app.
func adminCLI(exe string) (string, error) {
	inst, installed := menubar.WindowsInstalled()
	return menubar.FindWindowsCLI(exe, inst, installed, isFile, menubar.CheckInstalledCLI)
}

// isFile reports whether path is a regular file: Windows has no executable
// bit, so being leakguard.exe is what makes it runnable.
func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}
