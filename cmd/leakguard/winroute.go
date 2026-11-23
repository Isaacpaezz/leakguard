package main

import (
	"errors"
	"fmt"
)

// routeRow is one entry of the Windows route table (MIB_IPFORWARD_ROW2).
type routeRow struct {
	prefixLen uint8  // DestinationPrefix.PrefixLength; 0 is a default route
	ifIndex   uint32 // InterfaceIndex
	metric    uint32 // Metric
}

// windowsDefaultInterfaceFrom returns the alias of the adapter of the
// default route with the lowest metric: IPv4 first, IPv6 when there is no
// IPv4 one. routes reads the IPv4 or IPv6 table; alias names an adapter
// by its interface index.
func windowsDefaultInterfaceFrom(routes func(ipv6 bool) ([]routeRow, error), alias func(index uint32) (string, error)) (string, error) {
	v4, err := routes(false)
	if err != nil {
		return "", err
	}
	index, ok := bestDefaultRoute(v4)
	if !ok {
		// Missing or unreadable when IPv6 is off.
		v6, _ := routes(true)
		index, ok = bestDefaultRoute(v6)
	}
	if !ok {
		return "", errors.New("no default route found")
	}
	name, err := alias(index)
	if err != nil {
		return "", fmt.Errorf("cannot name the adapter of the default route (index %d): %w", index, err)
	}
	return name, nil
}

// bestDefaultRoute returns the interface of the default route with the
// lowest metric. Split routes such as OpenVPN's 0.0.0.0/1 are not default
// routes.
func bestDefaultRoute(rows []routeRow) (uint32, bool) {
	var best routeRow
	found := false
	for _, r := range rows {
		if r.prefixLen != 0 || r.ifIndex == 0 {
			continue
		}
		if !found || r.metric < best.metric {
			best, found = r, true
		}
	}
	return best.ifIndex, found
}
