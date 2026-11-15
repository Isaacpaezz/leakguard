package readme

import (
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
)

func TestReplaceSectionSwapsOnlyMarkedBody(t *testing.T) {
	doc := "intro\n<!-- BEGIN GENERATED: services -->\nold\n<!-- END GENERATED: services -->\noutro\n"
	got, err := ReplaceSection(doc, "services", "new body")
	if err != nil {
		t.Fatal(err)
	}
	want := "intro\n<!-- BEGIN GENERATED: services -->\nnew body\n<!-- END GENERATED: services -->\noutro\n"
	if got != want {
		t.Fatalf("ReplaceSection() =\n%q\nwant\n%q", got, want)
	}
}

func TestReplaceSectionFailsWhenMarkersMissing(t *testing.T) {
	_, err := ReplaceSection("no markers", "services", "x")
	if err == nil || !strings.Contains(err.Error(), "BEGIN GENERATED: services") {
		t.Fatalf("ReplaceSection() error = %v, want missing marker error", err)
	}
}

func TestServicesTable(t *testing.T) {
	svcs := []catalog.Service{
		{ID: "anthropic", Name: "Anthropic (Claude)", Status: catalog.StatusSupported,
			IPv4: []string{"a", "b"}, IPv6: []string{"c"}, Verified: "2026-11-15"},
		{ID: "openai", Name: "OpenAI", Status: catalog.StatusPlanned},
	}
	got := ServicesTable(svcs)
	for _, want := range []string{
		"| Service | Profile | Status | IPv4 ranges | IPv6 ranges | Last verified |",
		"| Anthropic (Claude) | `anthropic` | ✅ Supported | 2 | 1 | 2026-11-15 |",
		"| OpenAI | `openai` | 🗓️ Planned | – | – | – |",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("ServicesTable() missing line %q in:\n%s", want, got)
		}
	}
}

const changelog = `# Changelog

Intro text.

## [Unreleased]

### Added
- Something pending.

## [0.1.0] - 2026-11-20

### Added
- First release.

## [0.0.1] - 2026-11-01

- Old.
`

func TestLatestChangesPrefersNewestRelease(t *testing.T) {
	got, err := LatestChanges(changelog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "**v0.1.0** · 2026-11-20") || !strings.Contains(got, "**Added**") ||
		!strings.Contains(got, "- First release.") || strings.Contains(got, "Old.") || strings.Contains(got, "pending") {
		t.Fatalf("LatestChanges() =\n%s", got)
	}
}

func TestLatestChangesFallsBackToUnreleased(t *testing.T) {
	got, err := LatestChanges("# Changelog\n\n## [Unreleased]\n\n### Added\n- Pending thing.\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "Not released yet") || !strings.Contains(got, "- Pending thing.") {
		t.Fatalf("LatestChanges() =\n%s", got)
	}
}

func TestLatestChangesFailsWithoutSections(t *testing.T) {
	if _, err := LatestChanges("# Changelog\n"); err == nil {
		t.Fatal("LatestChanges() error = nil, want error")
	}
}

func TestReplaceSectionRejectsDuplicateMarkers(t *testing.T) {
	m := "<!-- BEGIN GENERATED: services -->\n<!-- END GENERATED: services -->\n"
	if _, err := ReplaceSection(m+m, "services", "x"); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("ReplaceSection() error = %v, want duplicate marker error", err)
	}
}

func TestLatestChangesHandlesKeepAChangelogEdgeCases(t *testing.T) {
	doc := "# Changelog\n\n##  [Unreleased]\n\n- Pending.\n\n## [0.2.0] - 2026-12-01 [YANKED]\n\n- Pulled.\n\n" +
		"[Unreleased]: https://example.com/compare\n[0.2.0]: https://example.com/v0.2.0\n"
	got, err := LatestChanges(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := "**v0.2.0** · 2026-12-01 · yanked\n\n- Pulled."
	if got != want {
		t.Fatalf("LatestChanges() = %q, want %q", got, want)
	}
}
