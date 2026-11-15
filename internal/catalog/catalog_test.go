package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validSupported() Service {
	return Service{
		ID:       "anthropic",
		Name:     "Anthropic (Claude)",
		Status:   StatusSupported,
		IPv4:     []string{"160.79.104.0/23"},
		IPv6:     []string{"2607:6bc0::/48"},
		Domains:  []string{"api.anthropic.com"},
		Sources:  []string{"https://bgp.he.net/AS399358"},
		Verified: "2026-11-15",
	}
}

func TestValidateAcceptsSupportedService(t *testing.T) {
	if err := validSupported().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestValidateAcceptsPlannedServiceWithoutRanges(t *testing.T) {
	s := Service{ID: "openai", Name: "OpenAI", Status: StatusPlanned, Domains: []string{"api.openai.com"}}
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Service)
		want   string
	}{
		{"bad id", func(s *Service) { s.ID = "Anthropic AI" }, "id"},
		{"empty name", func(s *Service) { s.Name = "" }, "name"},
		{"unknown status", func(s *Service) { s.Status = "beta" }, "status"},
		{"invalid ipv4", func(s *Service) { s.IPv4 = []string{"300.1.1.0/24"} }, "ipv4"},
		{"v6 in ipv4 list", func(s *Service) { s.IPv4 = []string{"2607:6bc0::/48"} }, "ipv4"},
		{"non-canonical prefix", func(s *Service) { s.IPv4 = []string{"160.79.104.1/23"} }, "ipv4"},
		{"v4 in ipv6 list", func(s *Service) { s.IPv6 = []string{"10.0.0.0/8"} }, "ipv6"},
		{"supported without ipv6", func(s *Service) { s.IPv6 = nil }, "ipv6"},
		{"supported without ipv4", func(s *Service) { s.IPv4 = nil }, "ipv4"},
		{"supported without sources", func(s *Service) { s.Sources = nil }, "sources"},
		{"supported without verified date", func(s *Service) { s.Verified = "" }, "verified"},
		{"bad verified date", func(s *Service) { s.Verified = "15/11/2026" }, "verified"},
		{"domain with scheme", func(s *Service) { s.Domains = []string{"https://claude.ai"} }, "domain"},
		{"upper-case domain", func(s *Service) { s.Domains = []string{"Claude.ai"} }, "domain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validSupported()
			tc.mutate(&s)
			err := s.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want error mentioning %q", err, tc.want)
			}
		})
	}
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const openaiJSON = `{"id":"openai","name":"OpenAI","status":"planned","domains":["api.openai.com"]}`
const anthropicJSON = `{"id":"anthropic","name":"Anthropic","status":"supported",
 "ipv4":["160.79.104.0/23"],"ipv6":["2607:6bc0::/48"],
 "sources":["https://bgp.he.net/AS399358"],"verified":"2026-11-15"}`

func TestLoadReturnsServicesSortedByID(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "openai.json", openaiJSON)
	writeFile(t, dir, "anthropic.json", anthropicJSON)
	writeFile(t, dir, "README.md", "ignored")

	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(got) != 2 || got[0].ID != "anthropic" || got[1].ID != "openai" {
		t.Fatalf("Load() ids = %v, want [anthropic openai]", ids(got))
	}
}

func TestLoadRejectsIDThatDoesNotMatchFileName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "claude.json", anthropicJSON)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "claude.json") {
		t.Fatalf("Load() error = %v, want file-name mismatch naming claude.json", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "openai.json", `{"id":"openai","name":"OpenAI","status":"planned","ipv7":[]}`)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "ipv7") {
		t.Fatalf("Load() error = %v, want unknown field error", err)
	}
}

func TestLoadRejectsInvalidService(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "openai.json", `{"id":"openai","name":"","status":"planned"}`)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "openai.json") {
		t.Fatalf("Load() error = %v, want validation error naming openai.json", err)
	}
}

func ids(s []Service) []string {
	out := make([]string, len(s))
	for i := range s {
		out[i] = s[i].ID
	}
	return out
}

func TestLoadFailsClosed(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("Load(missing dir) error = nil, want error")
	}
	if _, err := Load(t.TempDir()); err == nil || !strings.Contains(err.Error(), "no services") {
		t.Fatalf("Load(empty dir) error = %v, want no services error", err)
	}
}

func TestValidateRejectsUnsafeRanges(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Service)
		want   string
	}{
		{"whole ipv4 internet", func(s *Service) { s.IPv4 = []string{"0.0.0.0/0"} }, "too broad"},
		{"ipv4 wider than /8", func(s *Service) { s.IPv4 = []string{"160.0.0.0/7"} }, "too broad"},
		{"whole ipv6 internet", func(s *Service) { s.IPv6 = []string{"::/0"} }, "too broad"},
		{"ipv4-mapped ipv6", func(s *Service) { s.IPv6 = []string{"::ffff:1.2.3.0/120"} }, "ipv6"},
		{"duplicate range", func(s *Service) { s.IPv4 = []string{"160.79.104.0/23", "160.79.104.0/23"} }, "duplicate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validSupported()
			tc.mutate(&s)
			if err := s.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want error mentioning %q", err, tc.want)
			}
		})
	}
}
