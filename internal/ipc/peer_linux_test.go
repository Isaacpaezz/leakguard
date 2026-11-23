//go:build linux

package ipc

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

// linuxAdminGID looks up the first of sudo, wheel and admin like the daemon.
func linuxAdminGID(t *testing.T) (uint32, bool) {
	t.Helper()
	for _, name := range []string{"sudo", "wheel", "admin"} {
		if g, err := user.LookupGroup(name); err == nil {
			id, err := strconv.ParseUint(g.Gid, 10, 32)
			if err != nil {
				t.Fatalf("group %s has gid %q", name, g.Gid)
			}
			return uint32(id), true
		}
	}
	return 0, false
}

// A real connection from this process is accepted exactly when it runs as
// root or belongs to the administrators group.
func TestPeerCheckOnLinux(t *testing.T) {
	path := socketPath(t)
	var calls atomic.Int32
	startServer(t, &Server{Path: path, Handler: statusHandler(&calls), Chown: (&recorder{}).chown})
	_, err := Client{Path: path}.Status()

	admin, ok := linuxAdminGID(t)
	gs, _ := os.Getgroups()
	isAdmin := os.Getuid() == 0 || ok && (os.Getegid() == int(admin) || slices.Contains(gs, int(admin)))
	if isAdmin {
		if err != nil || calls.Load() != 1 {
			t.Fatalf("Status() as an administrator = %v (handler ran %d times)", err, calls.Load())
		}
		return
	}
	if err == nil || err.Error() != "not authorized" || calls.Load() != 0 {
		t.Fatalf("Status() outside the administrators group = %v (handler ran %d times)", err, calls.Load())
	}
}

func TestPeerCheckRejectsNonUnixConnsOnLinux(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := authorizePeer(a); err == nil {
		t.Fatal("authorizePeer(net.Pipe) = nil")
	}
}

const helperEnv = "LEAKGUARD_IPC_HELPER_SOCKET"

// TestHelperClient is the client half of TestPeerCheckForOtherUsers; it
// does nothing unless that test runs it in a child process.
func TestHelperClient(t *testing.T) {
	path := os.Getenv(helperEnv)
	if path == "" {
		return
	}
	if _, err := (Client{Path: path}).Status(); err != nil {
		fmt.Printf("RESULT: %v\n", err)
		return
	}
	fmt.Println("RESULT: ok")
}

// Real connections from other users, made by a child process that runs as
// nobody with chosen groups. Needs root to set the child's credentials.
func TestPeerCheckForOtherUsers(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to run a client as another user")
	}
	admin, ok := linuxAdminGID(t)
	if !ok {
		t.Skip("no sudo, wheel or admin group")
	}
	dir, err := os.MkdirTemp("", "lgpeer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The test binary lives in a private directory; nobody needs a copy.
	exe := filepath.Join(dir, "ipc.test")
	copyFile(t, exe)
	path := filepath.Join(dir, "s.sock")
	var calls atomic.Int32
	// The socket is opened to everyone so only the peer check decides.
	startServer(t, &Server{Path: path, Handler: statusHandler(&calls), Chown: (&recorder{}).chown,
		Chmod: func(p string, _ os.FileMode) error { return os.Chmod(p, 0o666) }})

	const nobody = 65534
	cases := []struct {
		name   string
		gid    uint32
		groups []uint32
		want   string
	}{
		{"not a member", nobody, nil, "not authorized"},
		{"supplementary member", nobody, []uint32{admin}, "ok"},
		{"primary member", admin, nil, "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run=^TestHelperClient$")
			cmd.Dir = dir
			cmd.Env = []string{helperEnv + "=" + path}
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
				Uid: nobody, Gid: tc.gid, Groups: tc.groups, NoSetGroups: false}}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("helper: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "RESULT: "+tc.want+"\n") {
				t.Fatalf("helper output = %q, want RESULT: %s", out, tc.want)
			}
		})
	}
	if calls.Load() != 2 {
		t.Fatalf("handler ran %d times, want 2 (administrators only)", calls.Load())
	}
}

func copyFile(t *testing.T, dst string) {
	t.Helper()
	src, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
