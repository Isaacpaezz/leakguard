package menubar

import (
	"strings"
	"testing"
)

const (
	sidSystem           = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidUsers            = "S-1-5-32-545"
	sidAuthenticated    = "S-1-5-11"
	sidCreatorOwner     = "S-1-3-0"
	sidAppPackages      = "S-1-15-2-1"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	sidAna              = "S-1-5-21-1-2-3-1001"
)

// programFilesACL is what %ProgramFiles%\leakguard inherits: full control
// for SYSTEM and Administrators, read and execute for Users and app
// packages, and the inherit-only CREATOR OWNER entry.
var programFilesACL = []ACE{
	{Type: aceAllowed, Flags: aceInherited, Mask: 0x001F01FF, SID: sidSystem},
	{Type: aceAllowed, Flags: aceInherited, Mask: 0x001F01FF, SID: sidAdministrators},
	{Type: aceAllowed, Flags: aceInherited, Mask: 0x001200A9, SID: sidUsers},
	{Type: aceAllowed, Flags: aceInherited | aceInheritOnly, Mask: 0x10000000, SID: sidCreatorOwner},
	{Type: aceAllowed, Flags: aceInherited, Mask: 0x001200A9, SID: sidAppPackages},
	{Type: aceAllowed, Flags: aceInherited, Mask: 0x001F01FF, SID: sidTrustedInstaller},
}

// S1: the installed copy runs elevated only when SYSTEM, Administrators
// or TrustedInstaller own it and nobody else may change it. Entries that
// cannot be understood refuse, so the check fails closed.
func TestAdminOnly(t *testing.T) {
	const path = `C:\Program Files\leakguard`
	with := func(extra ...ACE) []ACE { return append(append([]ACE{}, programFilesACL...), extra...) }
	tests := []struct {
		name    string
		owner   string
		dacl    []ACE
		present bool
		wantErr string
	}{
		{"Program Files, owned by Administrators", sidAdministrators, programFilesACL, true, ""},
		{"owned by TrustedInstaller", sidTrustedInstaller, programFilesACL, true, ""},
		{"owned by SYSTEM", sidSystem, programFilesACL, true, ""},
		{"owned by a user", sidAna, programFilesACL, true, `C:\Program Files\leakguard is owned by ` + sidAna + `, not by the administrators`},
		{"no access list: everyone may change it", sidAdministrators, nil, false, `C:\Program Files\leakguard has no access list, so anyone may change it`},
		{"empty access list: nobody may open it", sidAdministrators, nil, true, ""},
		{"users may write", sidAdministrators, with(ACE{Type: aceAllowed, Mask: 0x2, SID: sidUsers}), true, `C:\Program Files\leakguard may be changed by ` + sidUsers},
		{"a user may change its permissions", sidAdministrators, with(ACE{Type: aceAllowed, Mask: 0x40000, SID: sidAna}), true, "may be changed by " + sidAna},
		{"a user may delete it", sidAdministrators, with(ACE{Type: aceAllowed, Mask: 0x10000, SID: sidAna}), true, "may be changed by " + sidAna},
		{"generic write", sidAdministrators, with(ACE{Type: aceAllowed, Mask: 0x40000000, SID: sidAuthenticated}), true, "may be changed by " + sidAuthenticated},
		{"generic all", sidAdministrators, with(ACE{Type: aceAllowed, Mask: 0x10000000, SID: sidAuthenticated}), true, "may be changed by " + sidAuthenticated},
		{"add files to the folder", sidAdministrators, with(ACE{Type: aceAllowed, Mask: 0x4, SID: sidAuthenticated}), true, "may be changed by " + sidAuthenticated},
		{"delete children", sidAdministrators, with(ACE{Type: aceAllowed, Mask: 0x40, SID: sidAna}), true, "may be changed by " + sidAna},
		{"inherit-only write is not on this object", sidAdministrators, with(ACE{Type: aceAllowed, Flags: aceInheritOnly, Mask: 0x2, SID: sidAna}), true, ""},
		{"a deny entry only takes away", sidAdministrators, with(ACE{Type: aceDenied, Mask: 0x001F01FF, SID: sidAna}), true, ""},
		{"users may read", sidAdministrators, with(ACE{Type: aceAllowed, Mask: 0x00120089, SID: sidAna}), true, ""},
		{"an entry of another type", sidAdministrators, with(ACE{Type: 9, Mask: 0x1, SID: sidAna}), true, "an access entry leakguard cannot check (type 9)"},
	}
	for _, tc := range tests {
		err := AdminOnly(path, tc.owner, tc.dacl, tc.present)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.wantErr)
		}
	}
}
