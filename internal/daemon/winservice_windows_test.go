package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"golang.org/x/sys/windows"
)

// realWinHarness installs with the real directory ACL and owner calls, and
// a fake Service Control Manager.
func realWinHarness(t *testing.T) (WindowsService, string) {
	t.Helper()
	needElevated(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "leakguard.exe")
	if err := os.WriteFile(src, []byte("new binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := WindowsService{
		Binary:  filepath.Join(dir, "Program Files", "leakguard", "service", "leakguard.exe"),
		Command: wantCommand,
		SCM:     &fakeSCM{fail: map[string]error{}},
	}
	return w, src
}

// checkAdminOnlyDir checks that dir is a real directory owned by
// Administrators, with a protected DACL that lets only SYSTEM and
// Administrators write it.
func checkAdminOnlyDir(t *testing.T, dir string) {
	t.Helper()
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeIrregular != 0 || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("Lstat(%s) = %v, %v; want a real directory", dir, fi, err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		t.Errorf("owner of %s = %v, %v; want BUILTIN\\Administrators (%s)", dir, owner, err, sd)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("control of %s = %#x, %v; want a protected DACL (%s)", dir, control, err, sd)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL of %s = %v, %v", dir, dacl, err)
	}
	const write = windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
		windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || uint32(ace.Mask)&write == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			t.Errorf("%s can write %s (mask %#x)", sid, dir, ace.Mask)
		}
	}
}

// checkTrustedCopy checks that the service's copy is the new binary and
// that SYSTEM's service can trust it: owned by Administrators or SYSTEM,
// not a link, and nobody else may write it.
func checkTrustedCopy(t *testing.T, binary string) {
	t.Helper()
	f, err := config.OpenTrusted(binary)
	if err != nil {
		t.Fatalf("the service copy is not trusted: %v", err)
	}
	defer f.Close()
	data := make([]byte, 64)
	n, _ := f.Read(data)
	if string(data[:n]) != "new binary" {
		t.Fatalf("the service copy = %q", data[:n])
	}
}

// S6: Install creates the service directory in Program Files writable only
// by SYSTEM and Administrators, and the copy belongs to Administrators;
// an upgrade keeps both, and an entry someone else planted there (a DLL the
// service would load) is removed.
func TestWindowsInstallSecuresTheServiceDirectory(t *testing.T) {
	w, src := realWinHarness(t)
	if err := w.Install(src); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	dir := filepath.Dir(w.Binary)
	checkAdminOnlyDir(t, dir)
	checkTrustedCopy(t, w.Binary)

	planted := filepath.Join(dir, "version.dll")
	if err := os.WriteFile(planted, []byte("planted"), 0o644); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(planted, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Install(src); err != nil {
		t.Fatalf("second Install() = %v", err)
	}
	if _, err := os.Lstat(planted); !os.IsNotExist(err) {
		t.Errorf("the planted file is still there: %v", err)
	}
	checkAdminOnlyDir(t, dir)
	checkTrustedCopy(t, w.Binary)
	if err := w.Uninstall(); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(dir)); !os.IsNotExist(err) {
		t.Errorf("the leakguard folder is still there: %v", err)
	}
}

// A junction where the service directory goes is replaced by a real
// directory: the copy never lands where the junction points, and what it
// points to is not touched.
func TestWindowsInstallReplacesAJunctionAtTheServiceDirectory(t *testing.T) {
	w, src := realWinHarness(t)
	dir := filepath.Dir(w.Binary)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if fi, err := os.Lstat(dir); err != nil || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
		t.Fatalf("mklink /J did not make a junction: %v, %v", fi, err)
	}
	if err := w.Install(src); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	checkAdminOnlyDir(t, dir)
	checkTrustedCopy(t, w.Binary)
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 1 || entries[0].Name() != "keep.txt" {
		t.Fatalf("the junction's target holds %v, %v; want only keep.txt", entries, err)
	}
	if data, err := os.ReadFile(filepath.Join(target, "keep.txt")); err != nil || string(data) != "keep" {
		t.Fatalf("keep.txt = %q, %v", data, err)
	}
}
