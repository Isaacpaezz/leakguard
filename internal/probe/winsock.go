package probe

import (
	"encoding/binary"
	"errors"
	"syscall"
)

// Winsock errors of a refused connect on Windows: WFP's block filter fails
// the connect with WSAEACCES, a reset arrives as WSAECONNREFUSED.
const (
	wsaEACCES       syscall.Errno = 10013
	wsaECONNREFUSED syscall.Errno = 10061
)

// refused reports whether err is an immediate refusal on goos, the only
// proof that a block rule stopped the connection.
func refused(goos string, err error) bool {
	if goos == "windows" {
		// syscall.ECONNREFUSED is an invented value on Windows; the
		// portable tests' fake dialers return it.
		return errors.Is(err, wsaEACCES) || errors.Is(err, wsaECONNREFUSED) || errors.Is(err, syscall.ECONNREFUSED)
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

// Windows socket options that bind a socket to an interface (ws2ipdef.h).
const (
	ipprotoIP     = 0
	ipprotoIPv6   = 41
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

// unicastIfOption returns the setsockopt level, option and value that bind
// a Windows socket to the interface index: IP_UNICAST_IF takes the index in
// network byte order, IPV6_UNICAST_IF in host order.
func unicastIfOption(index int, ipv6 bool) (level, opt, value int) {
	if ipv6 {
		return ipprotoIPv6, ipv6UnicastIf, index
	}
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], uint32(index))
	return ipprotoIP, ipUnicastIf, int(binary.NativeEndian.Uint32(be[:]))
}
