package config

import (
	"errors"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The real adapter list reads, and no loopback or physical adapter on this
// machine is ever accepted as the VPN.
func TestRealWindowsAdaptersAreClassified(t *testing.T) {
	adapters, err := windowsAdapters()
	if err != nil {
		t.Fatalf("windowsAdapters() = %v", err)
	}
	if len(adapters) == 0 {
		t.Fatal("windowsAdapters() listed no adapter")
	}
	for _, a := range adapters {
		err := host.check(a.alias)
		switch {
		case a.ifType == winLoopback, a.ifType == winWiFi, a.ifType == winEthernet && a.hasMAC && !containsFold(a.description, winEthernetVPNDescriptions):
			if !errors.Is(err, ErrVPNRefused) {
				t.Errorf("check(%q) (type %d, %q) = %v, want a refusal", a.alias, a.ifType, a.description, err)
			}
		}
		t.Logf("%q type=%d up=%v mac=%v desc=%q: %v", a.alias, a.ifType, a.up, a.hasMAC, a.description, err)
	}
}

// PrepareDir gives the directory to Administrators with a protected ACL.
// It needs an elevated token, like the CI runner.
func TestPrepareDirSecuresTheDirectory(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token")
	}
	dir := filepath.Join(t.TempDir(), "leakguard")
	if err := PrepareDir(dir); err != nil {
		t.Fatalf("PrepareDir() = %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		t.Errorf("owner = %v, %v; want BUILTIN\\Administrators", owner, err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("control = %#x, %v; want a protected DACL", control, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	const write = windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
		windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER
	writers := map[string]bool{}
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
			t.Errorf("%s can write the directory (mask %#x)", sid, ace.Mask)
		}
		writers[sid.String()] = true
	}
	if !writers["S-1-5-18"] || !writers["S-1-5-32-544"] {
		t.Errorf("writers = %v, want SYSTEM and Administrators", writers)
	}
	// Saving works inside it.
	if err := Save(filepath.Join(dir, "config.json"), Config{VPNInterface: "WireGuard Tunnel", Services: []string{"anthropic"}}); err != nil {
		t.Fatalf("Save() = %v", err)
	}
}
