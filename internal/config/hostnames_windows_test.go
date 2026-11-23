package config

import "testing"

// hostNames returns interface names the host's rules refuse. A Windows
// alias may hold spaces and ";", so the invalid one holds a control
// character; the loopback is this machine's real loopback adapter; the
// physical one is a real-connection name no adapter has, refused by name.
func hostNames(t *testing.T) testNames {
	t.Helper()
	adapters, err := windowsAdapters()
	if err != nil {
		t.Fatalf("windowsAdapters() = %v", err)
	}
	loopback := ""
	for _, a := range adapters {
		if a.ifType == winLoopback {
			loopback = a.alias
			break
		}
	}
	if loopback == "" {
		t.Fatal("this machine has no loopback adapter")
	}
	return testNames{invalid: "ipsec0\tall", loopback: loopback, physical: "Ethernet 99"}
}
