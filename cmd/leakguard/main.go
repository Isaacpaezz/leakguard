// Command leakguard keeps chosen services off the real connection: traffic to
// them may leave only through the VPN interface.
package main

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/daemon"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
	"github.com/Isaacpaezz/leakguard/internal/nft"
	"github.com/Isaacpaezz/leakguard/internal/pf"
	"github.com/Isaacpaezz/leakguard/internal/probe"
)

func main() {
	if code, ok := runAsSystemService(os.Args[1:]); ok {
		os.Exit(code)
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, systemEnv()))
}

// systemEnv talks to the real system.
func systemEnv() Env {
	return Env{
		IsRoot:     systemIsRoot,
		Pfctl:      pf.ExecRunner{},
		Nft:        nft.ExecRunner{},
		Launchctl:  daemon.ExecRunner{},
		Systemctl:  daemon.SystemctlRunner{},
		Firewall:   systemFirewall,
		Services:   systemServices,
		Interfaces: systemInterfaces,
		Executable: func() (string, error) {
			exe, err := os.Executable()
			if err != nil {
				return "", err
			}
			return filepath.EvalSymlinks(exe)
		},
		Resolver:         net.DefaultResolver,
		Dial:             probe.BoundDial,
		DefaultInterface: systemDefaultInterface,
		Now:              time.Now,
		Socket:           ipc.DefaultPath,
		NotifySocket:     systemNotifySocket(),
		SCM:              systemSCM,
	}
}

func systemInterfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifs))
	for _, ifi := range ifs {
		i := Interface{Name: ifi.Name, Up: ifi.Flags&net.FlagUp != 0}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				ip, ok := netip.AddrFromSlice(n.IP)
				if ok && ip.Unmap().IsGlobalUnicast() {
					i.HasAddress = true
				}
			}
		}
		out = append(out, i)
	}
	return out, nil
}
