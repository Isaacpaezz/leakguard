package ipc

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// groups is a fake os/user.LookupGroup over name -> gid.
func groups(m map[string]string) groupLookup {
	return func(name string) (*user.Group, error) {
		gid, ok := m[name]
		if !ok {
			return nil, user.UnknownGroupError(name)
		}
		return &user.Group{Name: name, Gid: gid}, nil
	}
}

func TestAdminGroupPicksTheFirstThatExists(t *testing.T) {
	cases := []struct {
		name    string
		groups  map[string]string
		want    string
		wantGID uint32
		wantOK  bool
	}{
		{"sudo first", map[string]string{"admin": "4", "wheel": "10", "sudo": "27"}, "sudo", 27, true},
		{"wheel before admin", map[string]string{"admin": "4", "wheel": "10"}, "wheel", 10, true},
		{"admin last", map[string]string{"admin": "115"}, "admin", 115, true},
		{"garbled gid is skipped", map[string]string{"sudo": "x", "wheel": "10"}, "wheel", 10, true},
		{"none", map[string]string{"adm": "4", "staff": "50"}, "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, gid, ok := adminGroup(groups(tc.groups))
			if name != tc.want || gid != tc.wantGID || ok != tc.wantOK {
				t.Fatalf("adminGroup() = %q, %d, %v; want %q, %d, %v", name, gid, ok, tc.want, tc.wantGID, tc.wantOK)
			}
		})
	}
}

func TestSocketOwnership(t *testing.T) {
	failing := func(string) (*user.Group, error) { return nil, errors.New("cannot read /etc/group") }
	cases := []struct {
		name   string
		goos   string
		lookup groupLookup
		want   socketOwner
	}{
		// S2: macOS keeps root:admin (gid 80) 0660 whatever the group database says.
		{"darwin", "darwin", groups(nil), socketOwner{"admin", 80, 0o660}},
		{"linux sudo", "linux", groups(map[string]string{"sudo": "27", "wheel": "10"}), socketOwner{"sudo", 27, 0o660}},
		{"linux wheel", "linux", groups(map[string]string{"wheel": "10"}), socketOwner{"wheel", 10, 0o660}},
		// Fail closed: without an administrators group only root may connect.
		{"linux none", "linux", groups(nil), socketOwner{"root", 0, 0o600}},
		{"linux unreadable", "linux", failing, socketOwner{"root", 0, 0o600}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := socketOwnership(tc.goos, tc.lookup); got != tc.want {
				t.Fatalf("socketOwnership() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

const procStatus = "Name:\tleakguard-menu\nUmask:\t0022\nState:\tS (sleeping)\n" +
	"Pid:\t4242\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n" +
	"FDSize:\t64\nGroups:\t4 24 27 1000 \nNStgid:\t4242\n"

func TestParseProcStatus(t *testing.T) {
	uid, gid, gs, err := parseProcStatus(procStatus)
	if err != nil || uid != 1000 || gid != 1000 || len(gs) != 4 || gs[0] != 4 || gs[2] != 27 || gs[3] != 1000 {
		t.Fatalf("parseProcStatus() = %d, %d, %v, %v", uid, gid, gs, err)
	}
	// A process without supplementary groups has an empty Groups: line.
	empty := strings.Replace(procStatus, "Groups:\t4 24 27 1000 \n", "Groups:\t\n", 1)
	if _, _, gs, err := parseProcStatus(empty); err != nil || len(gs) != 0 {
		t.Fatalf("parseProcStatus(no groups) = %v, %v", gs, err)
	}
	// The effective ids are the second field.
	eff := strings.Replace(procStatus, "Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t27\t1000\t1000", 1)
	if _, gid, _, err := parseProcStatus(eff); err != nil || gid != 27 {
		t.Fatalf("parseProcStatus(effective gid) = %d, %v", gid, err)
	}
	bad := map[string]string{
		"empty":         "",
		"no groups":     strings.Replace(procStatus, "Groups:\t4 24 27 1000 \n", "", 1),
		"no gid":        strings.Replace(procStatus, "Gid:\t1000\t1000\t1000\t1000\n", "", 1),
		"no uid":        strings.Replace(procStatus, "Uid:\t1000\t1000\t1000\t1000\n", "", 1),
		"short gid":     strings.Replace(procStatus, "Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000", 1),
		"garbled group": strings.Replace(procStatus, "27 1000", "27 sudo", 1),
		"negative uid":  strings.Replace(procStatus, "Uid:\t1000\t1000", "Uid:\t1000\t-1", 1),
		"two gid lines": strings.Replace(procStatus, "FDSize", "Gid:\t27\t27\t27\t27\nFDSize", 1),
		"garbage":       "\x00\x01not a status file",
	}
	for name, data := range bad {
		if _, _, _, err := parseProcStatus(data); err == nil {
			t.Errorf("parseProcStatus(%s) = nil error", name)
		}
	}
}

// fakeProc writes /proc/<pid>/status under a temporary root.
func fakeProc(t *testing.T, pid, status string) string {
	t.Helper()
	root := t.TempDir()
	if status != "" {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// S8 on Linux: root, or a member of the administrators group, either as the
// primary group or as a supplementary group. Anyone else is refused.
func TestAuthorizeLinuxPeer(t *testing.T) {
	member := procStatus // Groups: 4 24 27 1000
	nonMember := strings.Replace(procStatus, "Groups:\t4 24 27 1000 \n", "Groups:\t4 24 1000 \n", 1)
	primary := strings.NewReplacer("Gid:\t1000\t1000\t1000\t1000", "Gid:\t27\t27\t27\t27",
		"Groups:\t4 24 27 1000 \n", "Groups:\t\n").Replace(procStatus)
	cases := []struct {
		name     string
		uid, gid uint32
		status   string
		admin    uint32
		hasAdmin bool
		ok       bool
	}{
		{"root without a status file", 0, 0, "", 27, true, true},
		{"root without an admin group", 0, 0, "", 0, false, true},
		{"supplementary member", 1000, 1000, member, 27, true, true},
		{"primary gid member", 1000, 27, primary, 27, true, true},
		{"non-member", 1000, 1000, nonMember, 27, true, false},
		{"missing status", 1000, 1000, "", 27, true, false},
		{"garbled status", 1000, 1000, "Uid:\tlots\nGid:\t?\n", 27, true, false},
		{"no admin group", 1000, 1000, member, 0, false, false},
		{"no admin group, gid 0", 1000, 0, strings.Replace(nonMember, "Gid:\t1000\t1000\t1000\t1000", "Gid:\t0\t0\t0\t0", 1), 0, false, false},
		// The pid was reused by another process: its ids differ from SO_PEERCRED.
		{"uid mismatch", 1001, 1000, member, 27, true, false},
		{"gid mismatch", 1000, 1001, member, 27, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := fakeProc(t, "4242", tc.status)
			err := authorizeLinuxPeer(tc.uid, tc.gid, 4242, root, tc.admin, tc.hasAdmin)
			if (err == nil) != tc.ok {
				t.Fatalf("authorizeLinuxPeer() = %v, want allowed %v", err, tc.ok)
			}
		})
	}
	if err := authorizeLinuxPeer(1000, 1000, 0, fakeProc(t, "0", member), 27, true); err == nil {
		t.Fatal("authorizeLinuxPeer(pid 0) = nil")
	}
}

// The server applies the chosen owner and mode, also root:root 0600.
func TestServerAppliesTheSocketOwner(t *testing.T) {
	path := socketPath(t)
	rec := &recorder{}
	startServer(t, &Server{Path: path, Handler: statusHandler(new(atomic.Int32)), Authorize: allowAll,
		Chown: rec.chown, owner: func() socketOwner { return socketOwner{"root", 0, 0o600} }})
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket = %v, %v; want mode 0600", info, err)
	}
	if got := strings.Join(rec.calls, "|"); got != "s.sock 0:0" {
		t.Fatalf("chown calls = %q, want root:root", got)
	}
	err = (&Server{Path: socketPath(t), Handler: statusHandler(new(atomic.Int32)), Authorize: allowAll,
		Chown: func(string, int, int) error { return errors.New("operation not permitted") },
		owner: func() socketOwner { return socketOwner{"sudo", 27, 0o660} }}).Serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "to root:sudo: operation not permitted") {
		t.Fatalf("Serve() = %v", err)
	}
}
