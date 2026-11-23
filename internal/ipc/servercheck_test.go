package ipc

import (
	"errors"
	"regexp"
	"strconv"
	"testing"
)

// Named pipe access rights (winnt.h).
const (
	fileReadData           = 0x0001
	fileWriteData          = 0x0002
	fileCreatePipeInstance = 0x0004 // FILE_APPEND_DATA on files
	fileReadAttributes     = 0x0080
	readControl            = 0x20000
	synchronize            = 0x100000
)

// S8 (SF1): interactive users may read and write the pipe, never create an
// instance of it: with FILE_CREATE_PIPE_INSTANCE a non-administrator could
// add an instance that answers status or swallows an administrator's set.
func TestPipeSDDLDeniesInstanceCreationToUsers(t *testing.T) {
	aces := regexp.MustCompile(`\(A;;([^;]+);;;IU\)`).FindAllStringSubmatch(pipeDACL, -1)
	if len(aces) != 1 {
		t.Fatalf("%s has %d entries for interactive users, want 1", pipeDACL, len(aces))
	}
	mask, err := strconv.ParseUint(aces[0][1], 0, 32)
	if err != nil {
		t.Fatalf("the interactive users' right %q is not a numeric mask (GW includes FILE_CREATE_PIPE_INSTANCE): %v", aces[0][1], err)
	}
	if mask&fileCreatePipeInstance != 0 {
		t.Errorf("interactive users get %#x, which includes FILE_CREATE_PIPE_INSTANCE", mask)
	}
	need := uint64(fileReadData | fileWriteData | fileReadAttributes | readControl | synchronize)
	if mask&need != need {
		t.Errorf("interactive users get %#x, want at least %#x to talk to the daemon", mask, need)
	}
	if mask != 0x12019b {
		t.Errorf("interactive users get %#x, want 0x12019b (FILE_GENERIC_READ | FILE_GENERIC_WRITE without FILE_CREATE_PIPE_INSTANCE)", mask)
	}
	// The client must ask for no more than interactive users get.
	if pipeClientRights&^mask != 0 {
		t.Errorf("the client asks for %#x, beyond the %#x interactive users get", pipeClientRights, mask)
	}
	if pipeDACL != "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)" {
		t.Errorf("pipeDACL = %q", pipeDACL)
	}
}

// S8 (SF1): the daemon owns its pipe as LocalSystem, so a client can tell
// the leakguard service from a pipe someone else created first; any other
// process keeps its default owner.
func TestPipeSecurityOwner(t *testing.T) {
	if got := pipeSecurity(sidLocalSystem); got != "O:SY"+pipeDACL {
		t.Errorf("pipeSecurity(LocalSystem) = %q", got)
	}
	for _, user := range []string{sidAdministrators, userSID, ""} {
		if got := pipeSecurity(user); got != pipeDACL {
			t.Errorf("pipeSecurity(%q) = %q, want %q", user, got, pipeDACL)
		}
	}
}

// S8 (SF1): a client talks only to a pipe owned by LocalSystem, the
// leakguard service; a pipe an administrator or anyone else created is
// refused.
func TestAuthorizeServer(t *testing.T) {
	if err := authorizeServer(sidLocalSystem); err != nil {
		t.Errorf("authorizeServer(LocalSystem) = %v", err)
	}
	for _, owner := range []string{sidAdministrators, userSID, "S-1-5-180", "s-1-5-18", "S-1-5-18-1", ""} {
		err := authorizeServer(owner)
		if !errors.Is(err, ErrUntrustedServer) || err.Error() != "the leakguard pipe is not served by the leakguard service" {
			t.Errorf("authorizeServer(%q) = %v, want %v", owner, err, ErrUntrustedServer)
		}
	}
}
