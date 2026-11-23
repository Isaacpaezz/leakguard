//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Isaacpaezz/leakguard/internal/menubar"
)

// These tests run headless on windows-latest: they never show a dialog.

// S1: Windows itself loads each tray icon, as systray does: the .ico in a
// file, read by LoadImageW at the default icon size.
func TestWindowsLoadsTheTrayIcons(t *testing.T) {
	user32 := windows.NewLazySystemDLL("user32.dll")
	loadImage, destroyIcon := user32.NewProc("LoadImageW"), user32.NewProc("DestroyIcon")
	const imageIcon, lrLoadFromFile, lrDefaultSize = 1, 0x10, 0x40
	dir := t.TempDir()
	for name, ico := range map[string][]byte{
		"protected": winIconProtected,
		"outline":   winIconOutline,
		"notsetup":  winIconNotSetUp,
	} {
		path := filepath.Join(dir, name+".ico")
		if err := os.WriteFile(path, ico, 0o644); err != nil {
			t.Fatal(err)
		}
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		h, _, err := loadImage.Call(0, uintptr(unsafe.Pointer(p)), imageIcon, 0, 0, lrLoadFromFile|lrDefaultSize)
		if h == 0 {
			t.Errorf("LoadImageW(%s) failed: %v", name, err)
			continue
		}
		destroyIcon.Call(h)
	}
}

// S1: the tray reads the Windows wording in the user's display language,
// and offers "Open at login" with no move-to-Applications step.
func TestWindowsPlatform(t *testing.T) {
	if got := language().Text(menubar.MsgMenuOpenAtLoginTip); got != menubar.UserLang().Text(menubar.MsgMenuOpenAtLoginTip) ||
		(got != "Abre este menú cada vez que inicias sesión en Windows; no pide contraseña" &&
			got != "Opens this menu every time you sign in to Windows; no password needed") {
		t.Errorf("open at login tip = %q", got)
	}
	exe := executable()
	p := newPlatform(exe, "").(windowsPlatform)
	t.Logf("exe %q, %%APPDATA%% %q, login menu %v", exe, p.appData, p.loginMenu())
	if p.appData == "" || p.loginMenu() != menubar.LoginItemToggle {
		t.Errorf("appData %q, login menu %v; want the toggle", p.appData, p.loginMenu())
	}
	if p.mustMove() {
		t.Error("mustMove = true on Windows")
	}
	if !isFile(exe) || isFile(filepath.Dir(exe)) {
		t.Errorf("isFile(%q) = %v, isFile(its folder) = %v", exe, isFile(exe), isFile(filepath.Dir(exe)))
	}
}
