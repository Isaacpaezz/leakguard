//go:build windows

package ipc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

var pipeCount atomic.Int32

// testPipe returns a pipe name no other test or daemon uses.
func testPipe() string {
	return fmt.Sprintf(`\\.\pipe\leakguard-test-%d-%d`, os.Getpid(), pipeCount.Add(1))
}

// startPipeServer runs s until the test ends and returns a function that
// stops it and returns Serve's error.
func startPipeServer(t *testing.T, s *Server) func() error {
	t.Helper()
	ready := make(chan struct{})
	s.ready = func() { close(ready) }
	s.deadline = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("Serve() = %v before it was ready", err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Serve() never became ready")
	}
	stopped := false
	var err error
	stop := func() error {
		if !stopped {
			stopped = true
			cancel()
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				err = errors.New("Serve() did not return after cancel")
			}
		}
		return err
	}
	t.Cleanup(func() { stop() })
	return stop
}

func pauseHandler(calls *atomic.Int32) Handler {
	return func(req Request) Response {
		calls.Add(1)
		return Response{OK: true, Status: &Status{Reason: ReasonPaused, VPNInterface: req.VPNInterface, Services: req.Services}}
	}
}

// currentUserIsAdmin applies the daemon's own rule to this process's token.
func currentUserIsAdmin(t *testing.T) bool {
	t.Helper()
	user, groups, err := tokenIdentity(windows.GetCurrentProcessToken())
	if err != nil {
		t.Fatalf("reading this process's token: %v", err)
	}
	return authorizeWindowsToken(user, groups) == nil
}

// S1, S8: the client and the daemon talk through the named pipe with the
// real token check: an administrator (CI runs elevated) is answered, anyone
// else gets "not authorized"; once the daemon stops, the client reports it.
func TestPipeRoundTripWithTheRealTokenCheck(t *testing.T) {
	path := testPipe()
	var calls atomic.Int32
	stop := startPipeServer(t, &Server{Path: path, Handler: pauseHandler(&calls)})
	c := Client{Path: path, CheckServer: anyServer}
	if !currentUserIsAdmin(t) {
		if _, err := c.Pause(); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("Pause() as a standard user = %v, want not authorized", err)
		}
		if calls.Load() != 0 {
			t.Fatalf("handler ran %d times for a standard user", calls.Load())
		}
		return
	}
	st, err := c.Set("Wintun VPN", []string{"anthropic"})
	if err != nil || st.VPNInterface != "Wintun VPN" || strings.Join(st.Services, ",") != "anthropic" {
		t.Fatalf("Set() = %+v, %v", st, err)
	}
	if st, err := c.Pause(); err != nil || st.Reason != ReasonPaused {
		t.Fatalf("Pause() = %+v, %v", st, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("handler ran %d times, want 2", calls.Load())
	}
	if err := stop(); err != nil {
		t.Fatalf("Serve() = %v after cancel", err)
	}
	if _, err := c.Status(); !errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("Status() after stop = %v, want ErrDaemonUnavailable", err)
	}
}

// S8, fail closed: a client that dials at the anonymous impersonation level
// hides its token, so it is refused even when it is an administrator.
func TestPipeRefusesAClientWithoutAReadableToken(t *testing.T) {
	path := testPipe()
	var calls atomic.Int32
	startPipeServer(t, &Server{Path: path, Handler: pauseHandler(&calls)})
	timeout := 2 * time.Second
	conn, err := winio.DialPipe(path, &timeout) // anonymous level
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(`{"cmd":"pause"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || line != `{"ok":false,"error":"not authorized"}`+"\n" {
		t.Fatalf("response = %q, %v; want not authorized", line, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("handler ran %d times for an anonymous client", calls.Load())
	}
}

// S8: the pipe carries exactly pipeDACL: a protected DACL that gives SYSTEM
// and Administrators full access and interactive users read and write
// without FILE_CREATE_PIPE_INSTANCE.
func TestPipeHasTheSecurityDescriptor(t *testing.T) {
	path := testPipe()
	startPipeServer(t, &Server{Path: path, Handler: pauseHandler(new(atomic.Int32))})
	timeout := 2 * time.Second
	conn, err := winio.DialPipe(path, &timeout)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	h := windows.Handle(conn.(interface{ Fd() uintptr }).Fd())
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetSecurityInfo: %v", err)
	}
	t.Logf("pipe security descriptor: %s", sd)
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("control = %#x, %v; want a protected DACL", control, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL() = %v, %v", dacl, err)
	}
	const (
		fileAll       = 0x1F01FF // FILE_ALL_ACCESS, what GA maps to
		fileReadWrite = 0x12019B // FILE_GENERIC_READ | FILE_GENERIC_WRITE without FILE_CREATE_PIPE_INSTANCE
	)
	// Each SID's mask, as written (generic) or as mapped for a file object.
	want := map[string][2]windows.ACCESS_MASK{
		sidLocalSystem:    {windows.GENERIC_ALL, fileAll},
		sidAdministrators: {windows.GENERIC_ALL, fileAll},
		"S-1-5-4":         {fileReadWrite, fileReadWrite},
	}
	if dacl.AceCount != uint16(len(want)) {
		t.Fatalf("DACL has %d entries, want %d", dacl.AceCount, len(want))
	}
	seen := map[string]bool{}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce(%d): %v", i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("entry %d has type %d, want allow", i, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		masks, ok := want[sid]
		if !ok || seen[sid] || (ace.Mask != masks[0] && ace.Mask != masks[1]) {
			t.Fatalf("entry %d allows %#x to %s; want only %v once each", i, ace.Mask, sid, want)
		}
		seen[sid] = true
	}
}

// anyServer accepts the test's own daemon, which does not run as
// LocalSystem.
func anyServer(net.Conn) error { return nil }

// S8 (SF1): a client refuses, before sending anything, a pipe that the
// leakguard service (LocalSystem) did not create: this test process is an
// administrator, not LocalSystem, so its pipe has another owner.
func TestPipeClientRefusesAServerThatIsNotTheService(t *testing.T) {
	path := testPipe()
	var calls atomic.Int32
	startPipeServer(t, &Server{Path: path, Handler: pauseHandler(&calls)})
	c := Client{Path: path}
	if _, err := c.Set("Wintun VPN", []string{"anthropic"}); !errors.Is(err, ErrUntrustedServer) ||
		err.Error() != "the leakguard pipe is not served by the leakguard service" {
		t.Fatalf("Set() = %v, want %v", err, ErrUntrustedServer)
	}
	if _, err := c.Status(); !errors.Is(err, ErrUntrustedServer) {
		t.Fatalf("Status() = %v, want %v", err, ErrUntrustedServer)
	}
	if calls.Load() != 0 {
		t.Fatalf("handler ran %d times for a refused server", calls.Load())
	}
	// The owner is read through a handle opened with the client's own
	// rights, and it is not LocalSystem.
	conn, err := dial(path)
	if err != nil {
		t.Fatalf("dial() = %v", err)
	}
	defer conn.Close()
	owner, err := pipeOwner(conn)
	if err != nil || owner == "" || owner == sidLocalSystem {
		t.Fatalf("pipeOwner() = %q, %v; want this process's owner, not LocalSystem", owner, err)
	}
	t.Logf("test pipe owner: %s", owner)
	if err := checkServer(conn); !errors.Is(err, ErrUntrustedServer) {
		t.Fatalf("checkServer() = %v, want %v", err, ErrUntrustedServer)
	}
}

// Two daemons must never serve at once: the second cannot take the pipe.
func TestPipeRefusesASecondDaemon(t *testing.T) {
	path := testPipe()
	startPipeServer(t, &Server{Path: path, Handler: pauseHandler(new(atomic.Int32))})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := (&Server{Path: path, Handler: pauseHandler(new(atomic.Int32))}).Serve(ctx)
	if err == nil || !strings.Contains(err.Error(), "another leakguard daemon") {
		t.Fatalf("second Serve() = %v, want a refusal", err)
	}
}

// The Windows default endpoint is the leakguard pipe.
func TestDefaultPathIsThePipe(t *testing.T) {
	if DefaultPath != `\\.\pipe\leakguard` {
		t.Fatalf("DefaultPath = %q", DefaultPath)
	}
}
