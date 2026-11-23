package menubar

import "fmt"

// ACE is one entry of a Windows access list (DACL), read by
// CheckInstalledCLI: its type, flags, access mask and the SID it names.
type ACE struct {
	Type  uint8
	Flags uint8
	Mask  uint32
	SID   string
}

// ACE types and flags (winnt.h).
const (
	aceAllowed     = 0x0
	aceDenied      = 0x1
	aceInheritOnly = 0x8
	aceInherited   = 0x10
)

// adminSIDs may own and change the installed copy: SYSTEM, the
// Administrators group and TrustedInstaller.
var adminSIDs = map[string]bool{
	"S-1-5-18":     true,
	"S-1-5-32-544": true,
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
}

// writeRights change a file or folder: generic all or write, changing its
// permissions or owner, deleting it, writing its data, attributes or
// extended attributes, adding files or folders, deleting children.
const writeRights = 0x10000000 | 0x40000000 | 0x00040000 | 0x00080000 | 0x00010000 |
	0x00000002 | 0x00000004 | 0x00000010 | 0x00000040 | 0x00000100

// AdminOnly checks the owner and access list of path, read by
// CheckInstalledCLI: SYSTEM, Administrators or TrustedInstaller must own
// it and nobody else may change it. present is false for a missing access
// list, which lets everyone in. Entries that apply only to children are
// skipped and deny entries only take rights away; any other kind of entry
// refuses, so the check fails closed.
func AdminOnly(path, owner string, dacl []ACE, present bool) error {
	if !adminSIDs[owner] {
		return fmt.Errorf("%s is owned by %s, not by the administrators", path, owner)
	}
	if !present {
		return fmt.Errorf("%s has no access list, so anyone may change it", path)
	}
	for _, e := range dacl {
		switch {
		case e.Flags&aceInheritOnly != 0, e.Type == aceDenied:
		case e.Type != aceAllowed:
			return fmt.Errorf("%s has an access entry leakguard cannot check (type %d)", path, e.Type)
		case !adminSIDs[e.SID] && e.Mask&writeRights != 0:
			return fmt.Errorf("%s may be changed by %s", path, e.SID)
		}
	}
	return nil
}
