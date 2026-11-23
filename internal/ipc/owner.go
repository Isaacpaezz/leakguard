package ipc

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// linuxAdminGroups are the Linux administrators groups, in order of
// preference: Debian and Ubuntu use sudo, Fedora and Arch use wheel, old
// Ubuntu releases use admin.
var linuxAdminGroups = []string{"sudo", "wheel", "admin"}

// groupLookup is os/user.LookupGroup; tests replace it.
type groupLookup func(name string) (*user.Group, error)

// adminGroup returns the first Linux administrators group that exists.
// ok is false when none exists or none can be read.
func adminGroup(lookup groupLookup) (name string, gid uint32, ok bool) {
	for _, n := range linuxAdminGroups {
		g, err := lookup(n)
		if err != nil {
			continue
		}
		id, err := strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			continue
		}
		return n, uint32(id), true
	}
	return "", 0, false
}

// socketOwner is who owns the daemon's socket and its mode. The server
// resolves it once, when it creates the socket, and checks every peer
// against the same group.
type socketOwner struct {
	group string
	gid   int
	mode  os.FileMode
	// admins is true when gid is an administrators group whose members may
	// connect; false means only root may (fail closed).
	admins bool
}

// socketOwnership picks the socket's owner: root:admin 0660 on macOS;
// root:<administrators group> 0660 on Linux, or root:root 0600 when the
// system has no administrators group, so only root may connect (fail closed).
func socketOwnership(goos string, lookup groupLookup) socketOwner {
	if goos != "linux" {
		return socketOwner{"admin", AdminGID, 0o660, true}
	}
	if name, gid, ok := adminGroup(lookup); ok {
		return socketOwner{name, int(gid), 0o660, true}
	}
	return socketOwner{"root", 0, 0o600, false}
}

// parseProcStatus reads the effective uid, the effective gid and the
// supplementary groups from a Linux /proc/<pid>/status file. Anything
// missing, repeated or not a number is an error.
func parseProcStatus(data string) (uid, gid uint32, groups []uint32, err error) {
	fields := map[string][]string{}
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || (key != "Uid" && key != "Gid" && key != "Groups") {
			continue
		}
		if _, dup := fields[key]; dup {
			return 0, 0, nil, fmt.Errorf("peer status has two %s lines", key)
		}
		fields[key] = strings.Fields(value)
	}
	ids := map[string][]uint32{}
	for _, key := range []string{"Uid", "Gid", "Groups"} {
		values, ok := fields[key]
		if !ok {
			return 0, 0, nil, fmt.Errorf("peer status has no %s line", key)
		}
		if key != "Groups" && len(values) != 4 {
			return 0, 0, nil, fmt.Errorf("peer status has %d %s values, want 4", len(values), key)
		}
		for _, v := range values {
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return 0, 0, nil, fmt.Errorf("peer status has an invalid %s value %q", key, v)
			}
			ids[key] = append(ids[key], uint32(n))
		}
	}
	return ids["Uid"][1], ids["Gid"][1], ids["Groups"], nil
}

// authorizeLinuxPeer decides on the SO_PEERCRED credentials of a peer: root
// is allowed; anyone else only when the administrators group exists and is
// the peer's effective gid or one of its supplementary groups, read from
// procRoot/<pid>/status. The ids in that file must match SO_PEERCRED, so a
// reused pid never lends its groups to another user.
func authorizeLinuxPeer(uid, gid uint32, pid int32, procRoot string, admin uint32, hasAdmin bool) error {
	if uid == 0 {
		return nil
	}
	if !hasAdmin {
		return fmt.Errorf("uid %d is not root and this system has no administrators group", uid)
	}
	if pid <= 0 {
		return fmt.Errorf("peer has no process id")
	}
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(int(pid)), "status"))
	if err != nil {
		return fmt.Errorf("could not read the peer's groups: %w", err)
	}
	suid, sgid, groups, err := parseProcStatus(string(data))
	if err != nil {
		return err
	}
	if suid != uid || sgid != gid {
		return errors.New("peer process credentials changed")
	}
	if !allowedGID(uid, append(groups, gid), admin) {
		return fmt.Errorf("uid %d is not an administrator", uid)
	}
	return nil
}
