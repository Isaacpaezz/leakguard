// Package catalog loads and validates the service catalog: the list of
// destinations (IP ranges and domains) that leakguard can protect.
package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Status tells whether a service can already be protected.
type Status string

const (
	// StatusSupported services have verified IP ranges and can be protected.
	StatusSupported Status = "supported"
	// StatusPlanned services are known but not yet protectable.
	StatusPlanned Status = "planned"
)

// Service is one protectable destination, stored as catalog/services/<id>.json.
type Service struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Status      Status   `json:"status"`
	IPv4        []string `json:"ipv4,omitempty"`
	IPv6        []string `json:"ipv6,omitempty"`
	Domains     []string `json:"domains,omitempty"`
	Sources     []string `json:"sources,omitempty"`
	Verified    string   `json:"verified,omitempty"`
	Notes       string   `json:"notes,omitempty"`
}

var (
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	domainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// Validate reports the first rule the service breaks.
func (s Service) Validate() error {
	if !idPattern.MatchString(s.ID) {
		return fmt.Errorf("id %q must be lower-case letters, digits and dashes", s.ID)
	}
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if s.Status != StatusSupported && s.Status != StatusPlanned {
		return fmt.Errorf("status %q must be %q or %q", s.Status, StatusSupported, StatusPlanned)
	}
	if err := validatePrefixes("ipv4", s.IPv4, true); err != nil {
		return err
	}
	if err := validatePrefixes("ipv6", s.IPv6, false); err != nil {
		return err
	}
	for _, d := range s.Domains {
		if !domainPattern.MatchString(d) {
			return fmt.Errorf("domain %q must be a lower-case host name without scheme or path", d)
		}
	}
	if s.Verified != "" {
		if _, err := time.Parse(time.DateOnly, s.Verified); err != nil {
			return fmt.Errorf("verified %q must be a YYYY-MM-DD date", s.Verified)
		}
	}
	if s.Status == StatusSupported {
		switch {
		case len(s.IPv4) == 0:
			return fmt.Errorf("supported services need at least one ipv4 range")
		case len(s.IPv6) == 0:
			return fmt.Errorf("supported services need at least one ipv6 range; without it the kill switch leaks on IPv6 networks")
		case len(s.Sources) == 0:
			return fmt.Errorf("supported services need sources that prove their ranges")
		case s.Verified == "":
			return fmt.Errorf("supported services need a verified date")
		}
	}
	return nil
}

// Narrowest allowed prefix lengths. Anything broader would block a large
// share of the internet and is almost certainly a mistake.
const (
	minIPv4Bits = 8
	minIPv6Bits = 16
)

func validatePrefixes(field string, prefixes []string, wantV4 bool) error {
	seen := make(map[netip.Prefix]bool, len(prefixes))
	for _, raw := range prefixes {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("%s range %q: %v", field, raw, err)
		}
		if p.Addr().Is4() != wantV4 || p.Addr().Is4In6() {
			return fmt.Errorf("%s range %q has the wrong address family", field, raw)
		}
		if p != p.Masked() {
			return fmt.Errorf("%s range %q is not canonical; use %s", field, raw, p.Masked())
		}
		minBits := minIPv6Bits
		if wantV4 {
			minBits = minIPv4Bits
		}
		if p.Bits() < minBits {
			return fmt.Errorf("%s range %q is too broad; the widest allowed is /%d", field, raw, minBits)
		}
		if seen[p] {
			return fmt.Errorf("%s range %q is a duplicate", field, raw)
		}
		seen[p] = true
	}
	return nil
}

// Load reads every *.json file in dir, validates it, and returns the services
// sorted by ID. Each file name must equal "<id>.json". A missing or empty
// directory is an error, so callers never mistake it for "nothing to protect".
func Load(dir string) ([]Service, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("catalog: no services found in %s", dir)
	}
	services := make([]Service, 0, len(paths))
	for _, path := range paths {
		s, err := loadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		services = append(services, s)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].ID < services[j].ID })
	return services, nil
}

func loadFile(path string) (Service, error) {
	var s Service
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, err
	}
	if err := s.Validate(); err != nil {
		return s, err
	}
	if want := s.ID + ".json"; filepath.Base(path) != want {
		return s, fmt.Errorf("file name must be %s to match id %q", want, s.ID)
	}
	return s, nil
}
