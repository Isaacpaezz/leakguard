package ipc

import (
	"errors"
	"strings"
	"testing"
)

// The groups of a standard user's token: none of them may talk to the daemon.
var userGroups = []tokenGroup{
	{"S-1-1-0", seGroupEnabled},      // Everyone
	{"S-1-5-32-545", seGroupEnabled}, // BUILTIN\Users
	{"S-1-5-4", seGroupEnabled},      // INTERACTIVE
	{"S-1-5-11", seGroupEnabled},     // Authenticated Users
}

const userSID = "S-1-5-21-1004336348-1177238915-682003330-1001"

// S8: on Windows only SYSTEM and BUILTIN\Administrators may talk to the
// daemon, also an administrator whose app runs without elevation (the group
// is then deny-only), like the admin group on macOS.
func TestAuthorizeWindowsToken(t *testing.T) {
	with := func(g ...tokenGroup) []tokenGroup { return append(append([]tokenGroup{}, userGroups...), g...) }
	cases := []struct {
		name   string
		user   string
		groups []tokenGroup
		ok     bool
	}{
		{"LocalSystem", sidLocalSystem, with(tokenGroup{sidAdministrators, seGroupEnabled}), true},
		{"LocalSystem without groups", sidLocalSystem, nil, true},
		{"SYSTEM group enabled", userSID, with(tokenGroup{sidLocalSystem, seGroupEnabled}), true},
		{"elevated administrator", userSID, with(tokenGroup{sidAdministrators, seGroupEnabled | 0x3}), true},
		{"administrator without elevation", userSID, with(tokenGroup{sidAdministrators, seGroupUseForDenyOnly}), true},
		{"administrators present but neither enabled nor deny-only", userSID, with(tokenGroup{sidAdministrators, 0x3}), false},
		{"SYSTEM group neither enabled nor deny-only", userSID, with(tokenGroup{sidLocalSystem, 0}), false},
		{"standard user", userSID, userGroups, false},
		{"similar SIDs", userSID, with(tokenGroup{"S-1-5-32-5440", seGroupEnabled}, tokenGroup{"S-1-5-180", seGroupEnabled},
			tokenGroup{"s-1-5-32-544x", seGroupEnabled}), false},
		{"empty token", "", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := authorizeWindowsToken(tc.user, tc.groups)
			if tc.ok && err != nil {
				t.Fatalf("authorizeWindowsToken() = %v, want allowed", err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "is not an administrator")) {
				t.Fatalf("authorizeWindowsToken() = %v, want not an administrator", err)
			}
		})
	}
}

// S8, fail closed: a client whose token cannot be read is refused.
func TestAuthorizeTokenRefusesWhenTheTokenCannotBeRead(t *testing.T) {
	cause := errors.New("ImpersonateNamedPipeClient: Unable to impersonate")
	err := authorizeToken(func() (string, []tokenGroup, error) {
		return sidLocalSystem, []tokenGroup{{sidAdministrators, seGroupEnabled}}, cause
	})
	if err == nil || !errors.Is(err, cause) || !strings.Contains(err.Error(), "could not read the client's token") {
		t.Fatalf("authorizeToken(read error) = %v, want a refusal wrapping the cause", err)
	}
	if err := authorizeToken(func() (string, []tokenGroup, error) { return userSID, userGroups, nil }); err == nil {
		t.Fatal("authorizeToken(standard user) = nil, want refused")
	}
	if err := authorizeToken(func() (string, []tokenGroup, error) {
		return userSID, []tokenGroup{{sidAdministrators, seGroupUseForDenyOnly}}, nil
	}); err != nil {
		t.Fatalf("authorizeToken(administrator) = %v, want allowed", err)
	}
}
