package ipc

import "fmt"

// Windows well-known SIDs and token group attributes (winnt.h).
const (
	sidLocalSystem        = "S-1-5-18"
	sidAdministrators     = "S-1-5-32-544"
	seGroupEnabled        = 0x00000004
	seGroupUseForDenyOnly = 0x00000010
)

// tokenGroup is one group of a Windows access token: its SID in string form
// and its SE_GROUP_* attributes.
type tokenGroup struct {
	SID        string
	Attributes uint32
}

// authorizeWindowsToken decides on a pipe client's Windows token: allowed
// when its user is LocalSystem, or when it holds SYSTEM or
// BUILTIN\Administrators either enabled or deny-only. Deny-only is an
// administrator whose app runs without elevation (UAC filters the group),
// the same people the admin group lets in on macOS.
func authorizeWindowsToken(user string, groups []tokenGroup) error {
	if user == sidLocalSystem {
		return nil
	}
	for _, g := range groups {
		if g.SID != sidLocalSystem && g.SID != sidAdministrators {
			continue
		}
		if g.Attributes&(seGroupEnabled|seGroupUseForDenyOnly) != 0 {
			return nil
		}
	}
	return fmt.Errorf("%s is not an administrator", user)
}

// authorizeToken reads a client's token with read and decides on it. A token
// that cannot be read is refused (fail closed).
func authorizeToken(read func() (user string, groups []tokenGroup, err error)) error {
	user, groups, err := read()
	if err != nil {
		return fmt.Errorf("could not read the client's token: %w", err)
	}
	return authorizeWindowsToken(user, groups)
}
