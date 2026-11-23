package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

// S1: on Windows WFP refuses a blocked connect with WSAEACCES, and a reset
// arrives as WSAECONNREFUSED; both prove the block. Elsewhere only
// ECONNREFUSED does, unchanged.
func TestRefusedPerOS(t *testing.T) {
	wrap := func(err error) error {
		return &net.OpError{Op: "dial", Net: "tcp4", Err: os.NewSyscallError("connectex", err)}
	}
	cases := []struct {
		goos string
		err  error
		want Outcome
	}{
		{"windows", wsaEACCES, Blocked},
		{"windows", wrap(wsaEACCES), Blocked},
		{"windows", wsaECONNREFUSED, Blocked},
		{"windows", wrap(wsaECONNREFUSED), Blocked},
		{"windows", syscall.ECONNREFUSED, Blocked},
		{"windows", syscall.Errno(10060), Untested}, // WSAETIMEDOUT
		{"windows", syscall.Errno(10051), Untested}, // WSAENETUNREACH
		{"windows", context.DeadlineExceeded, Untested},
		{"windows", nil, Leak},
		{"darwin", syscall.ECONNREFUSED, Blocked},
		{"darwin", wrap(syscall.ECONNREFUSED), Blocked},
		{"darwin", wsaEACCES, Untested},
		{"darwin", wsaECONNREFUSED, Untested},
		{"linux", syscall.ECONNREFUSED, Blocked},
		{"linux", wsaEACCES, Untested},
		{"linux", syscall.EACCES, Untested},
		{"linux", syscall.EHOSTUNREACH, Untested},
		{"linux", nil, Leak},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%v", tc.goos, tc.err), func(t *testing.T) {
			got, err := classifyOn(tc.goos, tc.err)
			if got != tc.want {
				t.Fatalf("classifyOn(%s, %v) = %v, want %v", tc.goos, tc.err, got, tc.want)
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("classifyOn(%s, %v) lost the cause: %v", tc.goos, tc.err, err)
			}
		})
	}
}

// S1: the Windows probe binds with IP_UNICAST_IF, whose IPv4 interface index
// is in network byte order, and IPV6_UNICAST_IF, in host order.
func TestUnicastIfOption(t *testing.T) {
	level, opt, value := unicastIfOption(7, false)
	if level != 0 || opt != 31 {
		t.Fatalf("IPv4 option = level %d opt %d, want IPPROTO_IP (0), IP_UNICAST_IF (31)", level, opt)
	}
	var mem [4]byte
	binary.NativeEndian.PutUint32(mem[:], uint32(value))
	if mem != [4]byte{0, 0, 0, 7} {
		t.Fatalf("IPv4 index 7 is %v in memory, want network byte order [0 0 0 7]", mem)
	}
	level, opt, value = unicastIfOption(7, true)
	if level != 41 || opt != 31 || value != 7 {
		t.Fatalf("IPv6 option = level %d opt %d value %d, want IPPROTO_IPV6 (41), IPV6_UNICAST_IF (31), 7", level, opt, value)
	}
	_, _, value = unicastIfOption(0x01020304, false)
	binary.NativeEndian.PutUint32(mem[:], uint32(value))
	if mem != [4]byte{1, 2, 3, 4} {
		t.Fatalf("IPv4 index 0x01020304 is %v in memory, want [1 2 3 4]", mem)
	}
}
