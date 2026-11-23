package ipc

import "errors"

// pipeDACL protects the daemon's named pipe on Windows: SYSTEM and
// Administrators get full access; interactive users get 0x12019b, that is
// FILE_GENERIC_READ | FILE_GENERIC_WRITE without FILE_CREATE_PIPE_INSTANCE
// (0x4), so an administrator's unelevated app can connect but no
// non-administrator can add an instance of the pipe that answers in the
// daemon's place. The token check then refuses anyone but administrators.
// P keeps inherited entries out.
const pipeDACL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)"

// pipeClientRights is what a client asks for when it opens the pipe:
// FILE_GENERIC_READ (0x120089, what GENERIC_READ maps to and
// GetNamedPipeInfo needs) and FILE_WRITE_DATA (0x2), within what pipeDACL
// gives interactive users. GENERIC_WRITE would map to FILE_GENERIC_WRITE,
// which includes FILE_CREATE_PIPE_INSTANCE, and be denied to them.
const pipeClientRights = 0x120089 | 0x0002

// ErrUntrustedServer means the pipe a client connected to was not created
// by the leakguard service (LocalSystem): someone else may have created it
// first, so the client sends nothing to it.
var ErrUntrustedServer = errors.New("the leakguard pipe is not served by the leakguard service")

// pipeSecurity is the security descriptor of the pipe created by a daemon
// running as user: owned by LocalSystem when the daemon runs as the
// leakguard service, which clients require (authorizeServer); any other
// process (a test, an administrator's shell) keeps its default owner and
// is refused by clients that do not inject their own check.
func pipeSecurity(user string) string {
	if user == sidLocalSystem {
		return "O:SY" + pipeDACL
	}
	return pipeDACL
}

// authorizeServer decides on the owner SID of the pipe a client connected
// to. Only LocalSystem passes: no one else can make a pipe owned by it
// without administrator privileges.
func authorizeServer(owner string) error {
	if owner == sidLocalSystem {
		return nil
	}
	return ErrUntrustedServer
}
