package ipc

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// socketPath returns a short socket path: Unix socket paths are limited to
// 104 bytes on macOS, and t.TempDir() can exceed that.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "lg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func TestReadRequestAccepts(t *testing.T) {
	cases := []struct {
		in   string
		want Request
	}{
		{`{"cmd":"status"}` + "\n", Request{Cmd: CmdStatus}},
		{`{"cmd":"disable"}` + "\n", Request{Cmd: CmdDisable}},
		{`{"cmd":"set","vpn_interface":"ipsec0","services":["anthropic"]}` + "\n",
			Request{Cmd: CmdSet, VPNInterface: "ipsec0", Services: []string{"anthropic"}}},
	}
	for _, tc := range cases {
		got, err := ReadRequest(strings.NewReader(tc.in))
		if err != nil {
			t.Fatalf("ReadRequest(%q) = %v", tc.in, err)
		}
		if got.Cmd != tc.want.Cmd || got.VPNInterface != tc.want.VPNInterface || strings.Join(got.Services, ",") != strings.Join(tc.want.Services, ",") {
			t.Fatalf("ReadRequest(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestReadRequestRejects(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"unknown command", `{"cmd":"reboot"}` + "\n", `unknown command "reboot"`},
		{"missing command", `{}` + "\n", `unknown command ""`},
		{"unknown field", `{"cmd":"status","admin":true}` + "\n", `unknown field "admin"`},
		{"trailing data", `{"cmd":"status"} {"cmd":"disable"}` + "\n", "unexpected data after the request"},
		{"no newline", `{"cmd":"status"}`, "incomplete request"},
		{"not json", "hello\n", "invalid request"},
		{"arguments to status", `{"cmd":"status","services":["anthropic"]}` + "\n", "status takes no arguments"},
		{"arguments to disable", `{"cmd":"disable","vpn_interface":"ipsec0"}` + "\n", "disable takes no arguments"},
		{"too large", `{"cmd":"set","vpn_interface":"` + strings.Repeat("a", MaxMessage) + `"}` + "\n", "request is larger than 65536 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadRequest(strings.NewReader(tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadRequest() = %v, want %q", err, tc.want)
			}
		})
	}
}

// The limit bounds what is read, so a peer cannot make the daemon buffer an
// endless stream.
func TestReadRequestReadsAtMostTheLimit(t *testing.T) {
	r := &countingReader{}
	if _, err := ReadRequest(r); err == nil {
		t.Fatal("ReadRequest() of an endless stream = nil")
	}
	if r.n > MaxMessage+1 {
		t.Fatalf("read %d bytes, want at most %d", r.n, MaxMessage+1)
	}
}

type countingReader struct{ n int }

func (c *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	c.n += len(p)
	return len(p), nil
}

func xucredBytes(version, uid uint32, groups ...uint32) []byte {
	b := make([]byte, xucredSize)
	binary.NativeEndian.PutUint32(b[0:], version)
	binary.NativeEndian.PutUint32(b[4:], uid)
	binary.NativeEndian.PutUint16(b[8:], uint16(len(groups)))
	for i, g := range groups {
		binary.NativeEndian.PutUint32(b[12+4*i:], g)
	}
	return b
}

func TestParseXucred(t *testing.T) {
	uid, groups, err := parseXucred(xucredBytes(0, 501, 20, 12, 80))
	if err != nil || uid != 501 || len(groups) != 3 || groups[0] != 20 || groups[2] != 80 {
		t.Fatalf("parseXucred() = %d, %v, %v", uid, groups, err)
	}
	bad := map[string][]byte{
		"short":        xucredBytes(0, 0)[:10],
		"version":      xucredBytes(1, 0),
		"many groups":  func() []byte { b := xucredBytes(0, 0); binary.NativeEndian.PutUint16(b[8:], 17); return b }(),
		"neg groups":   func() []byte { b := xucredBytes(0, 0); binary.NativeEndian.PutUint16(b[8:], 0xffff); return b }(),
		"cut groups":   xucredBytes(0, 501, 20, 80)[:16],
		"empty buffer": nil,
	}
	for name, b := range bad {
		if _, _, err := parseXucred(b); err == nil {
			t.Errorf("parseXucred(%s) = nil error", name)
		}
	}
}

func TestAllowed(t *testing.T) {
	cases := []struct {
		uid    uint32
		groups []uint32
		want   bool
	}{
		{0, nil, true},
		{501, []uint32{20, 80}, true},
		{501, []uint32{20, 12, 61}, false},
		{501, nil, false},
		{80, []uint32{20}, false}, // uid 80 is not group 80
	}
	for _, tc := range cases {
		if got := allowed(tc.uid, tc.groups); got != tc.want {
			t.Errorf("allowed(%d, %v) = %v, want %v", tc.uid, tc.groups, got, tc.want)
		}
	}
}

type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) chown(path string, uid, gid int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, filepath.Base(path)+" "+strconv.Itoa(uid)+":"+strconv.Itoa(gid))
	return nil
}

func allowAll(net.Conn) error { return nil }

// startServer runs s until the test ends and returns a function that stops
// it and returns Serve's error.
func startServer(t *testing.T, s *Server) func() error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan struct{})
	s.ready = func() { close(ready) }
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
	var once sync.Once
	var err error
	stop := func() error {
		once.Do(func() {
			cancel()
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				err = errors.New("Serve() did not return after cancel")
			}
		})
		return err
	}
	t.Cleanup(func() { stop() })
	return stop
}

func statusHandler(calls *atomic.Int32) Handler {
	return func(req Request) Response {
		calls.Add(1)
		switch req.Cmd {
		case CmdSet:
			return Response{OK: true, Status: &Status{VPNInterface: req.VPNInterface, Services: req.Services}}
		case CmdDisable:
			return Response{OK: true, Status: &Status{Reason: "paused"}}
		}
		return Response{OK: true, Status: &Status{Protected: true, VPNInterface: "ipsec0", VPNConnected: true,
			Services: []string{"anthropic"}, Catalog: []Service{{ID: "anthropic", Name: "Anthropic (Claude)", Status: "supported"}},
			LastRun: "2026-11-16T15:00:00Z Protected through ipsec0: anthropic"}}
	}
}

func TestServerAndClient(t *testing.T) {
	path := socketPath(t)
	rec := &recorder{}
	var calls atomic.Int32
	stop := startServer(t, &Server{Path: path, Handler: statusHandler(&calls), Authorize: allowAll, Chown: rec.chown})

	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket = %v, %v", info, err)
	}
	if info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, want 0660", info.Mode().Perm())
	}
	if got := strings.Join(rec.calls, "|"); got != "s.sock 0:80" {
		t.Fatalf("chown calls = %q, want root:admin", got)
	}

	c := Client{Path: path}
	st, err := c.Status()
	if err != nil || !st.Protected || st.VPNInterface != "ipsec0" || !st.VPNConnected || len(st.Catalog) != 1 || st.Catalog[0].Name != "Anthropic (Claude)" || st.LastRun == "" {
		t.Fatalf("Status() = %+v, %v", st, err)
	}
	st, err = c.Set("utun4", []string{"anthropic"})
	if err != nil || st.VPNInterface != "utun4" || strings.Join(st.Services, ",") != "anthropic" {
		t.Fatalf("Set() = %+v, %v", st, err)
	}
	st, err = c.Pause()
	if err != nil || st.Reason != "paused" {
		t.Fatalf("Pause() = %+v, %v", st, err)
	}
	if calls.Load() != 3 {
		t.Fatalf("handler ran %d times, want 3", calls.Load())
	}

	if err := stop(); err != nil {
		t.Fatalf("Serve() = %v after cancel", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket still exists after Serve returned: %v", err)
	}
	if _, err := c.Status(); !errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("Status() after stop = %v, want ErrDaemonUnavailable", err)
	}
}

func rawExchange(t *testing.T, path, request string) string {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	// A refused peer gets its answer and the connection is closed without
	// reading, so the write may fail with a broken pipe (Linux); the answer
	// is still there to read.
	conn.Write([]byte(request))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	return line
}

func TestServerRejectsBadRequestsWithoutRunningAnything(t *testing.T) {
	path := socketPath(t)
	var calls atomic.Int32
	startServer(t, &Server{Path: path, Handler: statusHandler(&calls), Authorize: allowAll, Chown: (&recorder{}).chown})
	for in, want := range map[string]string{
		`{"cmd":"reboot"}` + "\n":                 `{"ok":false,"error":"unknown command \"reboot\""}` + "\n",
		`{"cmd":"status","x":1}` + "\n":           `{"ok":false,"error":"invalid request: json: unknown field \"x\""}` + "\n",
		`{"cmd":"status"}{"cmd":"status"}` + "\n": `{"ok":false,"error":"unexpected data after the request"}` + "\n",
	} {
		if got := rawExchange(t, path, in); got != want {
			t.Errorf("response to %q = %q, want %q", in, got, want)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("handler ran %d times for invalid requests", calls.Load())
	}
}

func TestServerRefusesUnauthorizedPeers(t *testing.T) {
	path := socketPath(t)
	var calls atomic.Int32
	startServer(t, &Server{Path: path, Handler: statusHandler(&calls), Chown: (&recorder{}).chown,
		Authorize: func(net.Conn) error { return errors.New("uid 501 is not an administrator") }})
	if got := rawExchange(t, path, `{"cmd":"disable"}`+"\n"); got != `{"ok":false,"error":"not authorized"}`+"\n" {
		t.Fatalf("response = %q", got)
	}
	_, err := Client{Path: path}.Pause()
	if err == nil || err.Error() != "not authorized" || errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("Pause() = %v, want not authorized", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("handler ran %d times for an unauthorized peer", calls.Load())
	}
}

func TestServerReportsHandlerErrors(t *testing.T) {
	path := socketPath(t)
	startServer(t, &Server{Path: path, Authorize: allowAll, Chown: (&recorder{}).chown,
		Handler: func(Request) Response { return Response{Error: `service "openai" is not supported yet`} }})
	_, err := Client{Path: path}.Set("ipsec0", []string{"openai"})
	if err == nil || err.Error() != `service "openai" is not supported yet` {
		t.Fatalf("Set() = %v", err)
	}
}

func TestServerReplacesAStaleSocket(t *testing.T) {
	path := socketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	var calls atomic.Int32
	startServer(t, &Server{Path: path, Handler: statusHandler(&calls), Authorize: allowAll, Chown: (&recorder{}).chown})
	if _, err := (Client{Path: path}).Status(); err != nil {
		t.Fatalf("Status() = %v", err)
	}
}

func TestServerRefusesToRemoveOtherFiles(t *testing.T) {
	path := socketPath(t)
	os.WriteFile(path, []byte("important"), 0o644)
	err := (&Server{Path: path, Handler: statusHandler(new(atomic.Int32)), Authorize: allowAll, Chown: (&recorder{}).chown}).Serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "is not a socket") {
		t.Fatalf("Serve() = %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "important" {
		t.Fatalf("file = %q, Serve replaced it", data)
	}
}

func TestServerFailsWhenChownFails(t *testing.T) {
	path := socketPath(t)
	err := (&Server{Path: path, Handler: statusHandler(new(atomic.Int32)), Authorize: allowAll,
		Chown: func(string, int, int) error { return errors.New("operation not permitted") }}).Serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("Serve() = %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket left behind after a failed setup: %v", err)
	}
}

// A peer that connects and sends nothing must not hold the daemon forever.
func TestServerDropsSilentPeers(t *testing.T) {
	path := socketPath(t)
	var calls atomic.Int32
	s := &Server{Path: path, Handler: statusHandler(&calls), Authorize: allowAll, Chown: (&recorder{}).chown, deadline: 50 * time.Millisecond}
	startServer(t, s)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	// The deadline covers the response too, so the server just hangs up.
	line, err := bufio.NewReader(conn).ReadString('\n')
	if !errors.Is(err, io.EOF) {
		t.Fatalf("silent peer got %q, %v; want the connection closed after the deadline", line, err)
	}
	if calls.Load() != 0 {
		t.Fatal("handler ran for a silent peer")
	}
}

func TestClientReportsAMissingDaemon(t *testing.T) {
	path := socketPath(t)
	if _, err := (Client{Path: path}).Status(); !errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("Status() without a socket = %v, want ErrDaemonUnavailable", err)
	}
}

func TestServerWithoutHandlerOrPathFails(t *testing.T) {
	if err := (&Server{Handler: statusHandler(new(atomic.Int32))}).Serve(context.Background()); err == nil {
		t.Fatal("Serve() without a path = nil")
	}
	if err := (&Server{Path: socketPath(t)}).Serve(context.Background()); err == nil {
		t.Fatal("Serve() without a handler = nil")
	}
}

// A server that answers and hangs up before reading the request (as it does
// for unauthorized peers) breaks the client's write; the answer still counts.
func TestClientReadsTheAnswerAfterABrokenWrite(t *testing.T) {
	path := socketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte(`{"ok":false,"error":"not authorized"}` + "\n"))
		conn.Close()
	}()
	// A request larger than the socket buffers, so the write must fail.
	services := make([]string, 4000)
	for i := range services {
		services[i] = "anthropic"
	}
	_, err = Client{Path: path}.Set("ipsec0", services)
	if err == nil || err.Error() != "not authorized" {
		t.Fatalf("Set() = %v, want not authorized", err)
	}
}

// A second daemon must never take the socket of one that is still running.
func TestServerRefusesToTakeOverALiveSocket(t *testing.T) {
	path := socketPath(t)
	var calls atomic.Int32
	startServer(t, &Server{Path: path, Handler: statusHandler(&calls), Authorize: allowAll, Chown: (&recorder{}).chown})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := (&Server{Path: path, Handler: statusHandler(new(atomic.Int32)), Authorize: allowAll,
		Chown: (&recorder{}).chown}).Serve(ctx)
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second Serve() = %v, want already running", err)
	}
	if _, err := (Client{Path: path}).Status(); err != nil {
		t.Fatalf("first server no longer answers: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("first server handled %d requests, want 1", calls.Load())
	}
}
