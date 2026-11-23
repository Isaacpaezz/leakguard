package config

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsAdapters lists the network adapters with GetAdaptersAddresses,
// connected or not.
func windowsAdapters() ([]windowsAdapter, error) {
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(15000)
	for tries := 0; tries < 5; tries++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var out []windowsAdapter
		for a := first; a != nil; a = a.Next {
			out = append(out, windowsAdapter{
				alias:       windows.UTF16PtrToString(a.FriendlyName),
				description: windows.UTF16PtrToString(a.Description),
				ifType:      a.IfType,
				up:          a.OperStatus == windows.IfOperStatusUp,
				hasMAC:      a.PhysicalAddressLength > 0,
			})
		}
		return out, nil
	}
	return nil, errors.New("GetAdaptersAddresses: the adapter list keeps growing")
}
