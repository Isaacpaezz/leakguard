//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"net"
	"runtime"

	"golang.org/x/sys/windows"
)

var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// authorizePeer accepts a pipe client whose token is LocalSystem or holds
// SYSTEM or BUILTIN\Administrators, enabled or deny-only (an administrator
// without elevation). A token that cannot be read is refused.
func authorizePeer(conn net.Conn, _ socketOwner) error {
	return authorizeToken(func() (string, []tokenGroup, error) { return clientToken(conn) })
}

// clientToken reads the user and groups of a pipe client's token by
// impersonating it on a locked OS thread of its own.
func clientToken(conn net.Conn) (string, []tokenGroup, error) {
	f, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return "", nil, errors.New("not a named pipe connection")
	}
	pipe := windows.Handle(f.Fd())
	type result struct {
		token windows.Token
		err   error
	}
	done := make(chan result, 1)
	go func() {
		// Impersonation changes the thread's identity. The thread is only
		// handed back to Go when RevertToSelf worked; otherwise it stays
		// locked and ends with this goroutine.
		runtime.LockOSThread()
		if r, _, err := procImpersonateNamedPipeClient.Call(uintptr(pipe)); r == 0 {
			runtime.UnlockOSThread()
			done <- result{err: fmt.Errorf("ImpersonateNamedPipeClient: %w", err)}
			return
		}
		var token windows.Token
		terr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
		if err := windows.RevertToSelf(); err != nil {
			if terr == nil {
				token.Close()
			}
			done <- result{err: fmt.Errorf("RevertToSelf: %w", err)}
			return
		}
		runtime.UnlockOSThread()
		if terr != nil {
			done <- result{err: fmt.Errorf("OpenThreadToken: %w", terr)}
			return
		}
		done <- result{token: token}
	}()
	r := <-done
	if r.err != nil {
		return "", nil, r.err
	}
	defer r.token.Close()
	return tokenIdentity(r.token)
}

// tokenIdentity returns a token's user SID and its groups.
func tokenIdentity(token windows.Token) (string, []tokenGroup, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return "", nil, fmt.Errorf("reading the token's user: %w", err)
	}
	tg, err := token.GetTokenGroups()
	if err != nil {
		return "", nil, fmt.Errorf("reading the token's groups: %w", err)
	}
	var groups []tokenGroup
	for _, g := range tg.AllGroups() {
		groups = append(groups, tokenGroup{SID: g.Sid.String(), Attributes: g.Attributes})
	}
	return user.User.Sid.String(), groups, nil
}
