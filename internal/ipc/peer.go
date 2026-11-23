package ipc

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// xucred is the macOS struct returned by LOCAL_PEERCRED:
//
//	struct xucred {
//		u_int   cr_version;       // XUCRED_VERSION, 0
//		uid_t   cr_uid;           // effective user id
//		short   cr_ngroups;       // number of groups
//		gid_t   cr_groups[16];    // groups
//	};
//
// cr_ngroups is followed by two bytes of padding.
const (
	xucredVersion   = 0
	xucredMaxGroups = 16
	xucredGroupsOff = 12
	xucredSize      = xucredGroupsOff + 4*xucredMaxGroups
)

// parseXucred decodes a struct xucred in native byte order.
func parseXucred(b []byte) (uid uint32, groups []uint32, err error) {
	if len(b) < xucredGroupsOff {
		return 0, nil, fmt.Errorf("peer credentials are %d bytes, too short", len(b))
	}
	if v := binary.NativeEndian.Uint32(b[0:]); v != xucredVersion {
		return 0, nil, fmt.Errorf("unknown peer credentials version %d", v)
	}
	uid = binary.NativeEndian.Uint32(b[4:])
	n := int(int16(binary.NativeEndian.Uint16(b[8:])))
	if n < 0 || n > xucredMaxGroups {
		return 0, nil, fmt.Errorf("invalid peer group count %d", n)
	}
	if len(b) < xucredGroupsOff+4*n {
		return 0, nil, errors.New("peer credentials are truncated")
	}
	groups = make([]uint32, n)
	for i := range groups {
		groups[i] = binary.NativeEndian.Uint32(b[xucredGroupsOff+4*i:])
	}
	return uid, groups, nil
}

// allowed reports whether a peer may talk to the daemon: root, or a member
// of group admin.
func allowed(uid uint32, groups []uint32) bool {
	return allowedGID(uid, groups, AdminGID)
}

// allowedGID reports whether uid is root or groups contain admin.
func allowedGID(uid uint32, groups []uint32, admin uint32) bool {
	if uid == 0 {
		return true
	}
	for _, g := range groups {
		if g == admin {
			return true
		}
	}
	return false
}
