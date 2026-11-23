package config

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// What a non-administrator would plant: a config that pauses protection.
const plantedConfig = `{"vpn_interface":"WireGuard Tunnel","services":["anthropic"],"paused":true}`

// junction makes link a directory junction to target, as any user can.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if !isReparsePoint(t, link) {
		t.Fatalf("mklink /J did not make a reparse point at %s", link)
	}
}

func isReparsePoint(t *testing.T, path string) bool {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s) = %v", path, err)
	}
	return fi.Sys().(*syscall.Win32FileAttributeData).FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// setSecurity sets the owner (nil: unchanged) and the DACL of path.
func setSecurity(t *testing.T, path string, owner *windows.SID, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo(%s) = %v", path, err)
	}
}

func securityOf(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// currentUser is this process's user SID: what owns a non-administrator's
// files.
func currentUser(t *testing.T) *windows.SID {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid
}

func names(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(data)
}

// S7: %ProgramData%\leakguard created first as a junction by a user is
// never followed: PrepareDir removes the junction and makes a real
// directory; the target keeps its files and its ACL, and Save writes into
// the real directory.
func TestPrepareDirReplacesAJunctionAndNeverTouchesItsTarget(t *testing.T) {
	needElevated(t)
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "config.json"), plantedConfig)
	before := securityOf(t, target)
	dir := filepath.Join(root, "leakguard")
	junction(t, dir, target)

	if err := PrepareDir(dir); err != nil {
		t.Fatalf("PrepareDir() = %v", err)
	}
	if isReparsePoint(t, dir) {
		t.Fatalf("PrepareDir() left the junction at %s", dir)
	}
	checkSecured(t, dir)
	if got := names(t, dir); got != "" {
		t.Errorf("the new directory holds %q, want nothing (the junction was followed)", got)
	}
	if after := securityOf(t, target); after != before {
		t.Errorf("the junction's target changed its security:\nbefore %s\nafter  %s", before, after)
	}
	if got := readFile(t, filepath.Join(target, "config.json")); got != plantedConfig {
		t.Errorf("the target's config.json = %q, want it untouched", got)
	}
	if err := Save(filepath.Join(dir, "config.json"), Config{VPNInterface: "WireGuard Tunnel", Services: []string{"anthropic"}}); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	if got := readFile(t, filepath.Join(target, "config.json")); got != plantedConfig {
		t.Errorf("Save() wrote through the old junction: target config.json = %q", got)
	}
	if got := names(t, target); got != "config.json" {
		t.Errorf("target holds %q, want only config.json", got)
	}
}

// S7: a directory a user created first, with their own ACL and files in
// it (a config that pauses protection, a hard link to a file elsewhere, a
// junction), is taken over: owner Administrators, protected ACL, and every
// planted entry removed without touching what it points to.
func TestPrepareDirTakesOverADirectoryAUserCreated(t *testing.T) {
	needElevated(t)
	root := t.TempDir()
	dir := filepath.Join(root, "leakguard")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	user := currentUser(t)
	setSecurity(t, dir, user, "D:P(A;OICI;FA;;;WD)")
	configPath := filepath.Join(dir, "config.json")
	writeFile(t, configPath, plantedConfig)
	setSecurity(t, configPath, user, "D:P(A;;FA;;;WD)")
	outside := filepath.Join(root, "outside.txt")
	writeFile(t, outside, "keep")
	if err := os.Link(outside, filepath.Join(dir, "leakguard.log")); err != nil {
		t.Fatalf("os.Link() = %v", err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "keep.txt"), "keep")
	junction(t, filepath.Join(dir, "stats.json"), target)
	t.Logf("before: %s holds %q; %s", dir, names(t, dir), securityOf(t, dir))

	if err := PrepareDir(dir); err != nil {
		t.Fatalf("PrepareDir() = %v", err)
	}
	checkSecured(t, dir)
	if got := names(t, dir); got != "" {
		t.Errorf("after PrepareDir %s holds %q, want every planted entry removed", dir, got)
	}
	if got := readFile(t, outside); got != "keep" {
		t.Errorf("the hard link's other name = %q, want it untouched", got)
	}
	if got := readFile(t, filepath.Join(target, "keep.txt")); got != "keep" {
		t.Errorf("the junction's target file = %q, want it untouched", got)
	}
	if _, err := Load(configPath); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("Load() = %v, want ErrNotConfigured (the planted config is gone)", err)
	}
}

// S7: Load refuses a config someone other than SYSTEM and Administrators
// owns or may write, and a link, so the daemon never runs one a user
// planted; Save's own file is owned by Administrators and loads.
func TestLoadRefusesAConfigSomeoneElseMayWrite(t *testing.T) {
	needElevated(t)
	dir := filepath.Join(t.TempDir(), "leakguard")
	path := filepath.Join(dir, "config.json")
	want := Config{VPNInterface: "WireGuard Tunnel", Services: []string{"anthropic"}}
	save := func() {
		t.Helper()
		if err := Save(path, want); err != nil {
			t.Fatalf("Save() = %v", err)
		}
	}
	save()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if owner, _, err := sd.Owner(); err != nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		t.Errorf("Save()'s file is owned by %v, %v; want BUILTIN\\Administrators", owner, err)
	}
	if got, err := Load(path); err != nil || got.VPNInterface != want.VPNInterface {
		t.Fatalf("Load() of Save()'s file = %+v, %v (%s)", got, err, securityOf(t, path))
	}
	refused := func(what, reason string) {
		t.Helper()
		got, err := Load(path)
		if !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: Load() = %+v, %v; want ErrUnsafePath with %q (%s)", what, got, err, reason, securityOf(t, path))
		}
	}
	setSecurity(t, path, nil, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)")
	refused("Users may write it", "writable by S-1-5-32-545")
	save()
	setSecurity(t, path, currentUser(t), "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	refused("a user owns it", "is owned by "+currentUser(t).String())

	realPath := filepath.Join(dir, "real.json")
	// Save swept the user-owned config.json away.
	if err := Save(realPath, want); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, path); err != nil {
		t.Fatalf("os.Symlink() = %v", err)
	}
	refused("a symbolic link", "is a link (reparse point)")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(realPath, path); err != nil {
		t.Fatalf("os.Link() = %v", err)
	}
	refused("a hard link", "has 2 hard links")
}

// S7: while someone holds the directory open for adding files (a handle
// kept from before the takeover would outlive the new ACL), PrepareDir
// refuses; once it is closed, PrepareDir takes the directory over.
func TestPrepareDirRefusesADirectoryHeldOpenForWriting(t *testing.T) {
	needElevated(t)
	dir := filepath.Join(t.TempDir(), "leakguard")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "leftover.txt"), "x")
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.FILE_WRITE_DATA /* FILE_ADD_FILE */, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("CreateFile() = %v", err)
	}
	err = PrepareDir(dir)
	windows.CloseHandle(h)
	if err == nil || !strings.Contains(err.Error(), "cannot open "+dir) {
		t.Fatalf("PrepareDir() with a writer holding the directory = %v, want a refusal", err)
	}
	t.Logf("refused: %v", err)
	if err := PrepareDir(dir); err != nil {
		t.Fatalf("PrepareDir() after the writer closed = %v", err)
	}
	checkSecured(t, dir)
}
