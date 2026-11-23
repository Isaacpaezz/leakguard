package ipc

import (
	"bufio"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// countingConn counts the bytes the server read before authorizing.
type countingConn struct {
	net.Conn
	read atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(int64(n))
	return n, err
}

// exchangeReadFirst runs one connection through a server that reads the
// request before it authorizes the peer, as on Windows, where the client's
// token can only be read after data came through the pipe. It returns the
// response line and how many bytes the server had read when it authorized.
func exchangeReadFirst(t *testing.T, s *Server, authorize func() error, request string) (string, int64) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	cc := &countingConn{Conn: server}
	var readAtAuth atomic.Int64
	readAtAuth.Store(-1)
	s.readFirst = true
	s.Authorize = func(c net.Conn) error {
		if c != net.Conn(cc) {
			t.Error("Authorize got another connection")
		}
		readAtAuth.Store(cc.read.Load())
		return authorize()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handle(cc)
	}()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	go client.Write([]byte(request))
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	<-done
	return line, readAtAuth.Load()
}

// S8: when the platform reads first, an unauthorized peer still learns only
// "not authorized", even for a malformed request, and nothing runs.
func TestReadFirstServerRefusesUnauthorizedPeersAfterReading(t *testing.T) {
	refuse := func() error { return errors.New("S-1-5-21-1 is not an administrator") }
	for _, in := range []string{`{"cmd":"pause"}` + "\n", `{"cmd":"reboot"}` + "\n", `{"cmd":"status","x":1}` + "\n"} {
		var calls atomic.Int32
		got, read := exchangeReadFirst(t, &Server{Handler: statusHandlerCount(&calls)}, refuse, in)
		if got != `{"ok":false,"error":"not authorized"}`+"\n" {
			t.Errorf("response to %q = %q, want not authorized", in, got)
		}
		if read != int64(len(in)) {
			t.Errorf("authorized after reading %d bytes of %q, want the whole request", read, in)
		}
		if calls.Load() != 0 {
			t.Errorf("handler ran %d times for an unauthorized peer", calls.Load())
		}
	}
}

func TestReadFirstServerAnswersAuthorizedPeers(t *testing.T) {
	allow := func() error { return nil }
	var calls atomic.Int32
	got, read := exchangeReadFirst(t, &Server{Handler: statusHandlerCount(&calls)}, allow, `{"cmd":"pause"}`+"\n")
	if got != `{"ok":true,"status":{"protected":false,"reason":"paused","vpn_interface":"","vpn_connected":false,"services":null,"catalog":null}}`+"\n" {
		t.Fatalf("response = %q", got)
	}
	if read != int64(len(`{"cmd":"pause"}`+"\n")) || calls.Load() != 1 {
		t.Fatalf("read %d bytes before authorizing, handler ran %d times", read, calls.Load())
	}
	got, _ = exchangeReadFirst(t, &Server{Handler: statusHandlerCount(&calls)}, allow, `{"cmd":"reboot"}`+"\n")
	if got != `{"ok":false,"error":"unknown command \"reboot\""}`+"\n" || calls.Load() != 1 {
		t.Fatalf("response to a bad request = %q, handler ran %d times", got, calls.Load())
	}
}

// statusHandlerCount answers like the daemon to pause and counts calls.
func statusHandlerCount(calls *atomic.Int32) Handler {
	return func(req Request) Response {
		calls.Add(1)
		return Response{OK: true, Status: &Status{Reason: ReasonPaused}}
	}
}
