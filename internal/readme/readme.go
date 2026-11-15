// Package readme renders the generated sections of the project README, so the
// landing page always reflects the service catalog and the latest release.
package readme

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
)

// ReplaceSection replaces the text between the BEGIN/END GENERATED markers
// named name, keeping the markers and everything outside them.
func ReplaceSection(doc, name, body string) (string, error) {
	begin := "<!-- BEGIN GENERATED: " + name + " -->"
	end := "<!-- END GENERATED: " + name + " -->"
	switch n := strings.Count(doc, begin); {
	case n == 0:
		return "", fmt.Errorf("marker %q not found", begin)
	case n > 1:
		return "", fmt.Errorf("marker %q appears more than once", begin)
	}
	i := strings.Index(doc, begin)
	j := strings.Index(doc[i:], end)
	if j < 0 {
		return "", fmt.Errorf("marker %q not found after %q", end, begin)
	}
	return doc[:i+len(begin)] + "\n" + strings.TrimSpace(body) + "\n" + doc[i+j:], nil
}

// ServicesTable renders the catalog as a Markdown table.
func ServicesTable(services []catalog.Service) string {
	var b strings.Builder
	b.WriteString("| Service | Profile | Status | IPv4 ranges | IPv6 ranges | Last verified |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, s := range services {
		status := "🗓️ Planned"
		if s.Status == catalog.StatusSupported {
			status = "✅ Supported"
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s | %s |\n",
			s.Name, s.ID, status, count(len(s.IPv4)), count(len(s.IPv6)), dash(s.Verified))
	}
	return b.String()
}

func count(n int) string {
	if n == 0 {
		return "–"
	}
	return fmt.Sprint(n)
}

func dash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

var (
	releaseHeading = regexp.MustCompile(`^##\s+\[([^\]]+)\](?:\s+-\s+(\S+))?(\s+\[YANKED\])?\s*$`)
	linkReference  = regexp.MustCompile(`^\[[^\]]+\]:\s+\S+`)
)

// LatestChanges returns the newest released CHANGELOG section, or the
// Unreleased section when nothing has been released yet.
func LatestChanges(changelog string) (string, error) {
	type section struct {
		version, date string
		yanked        bool
		body          []string
	}
	var sections []section
	for _, line := range strings.Split(changelog, "\n") {
		if m := releaseHeading.FindStringSubmatch(line); m != nil {
			sections = append(sections, section{version: m[1], date: m[2], yanked: m[3] != ""})
			continue
		}
		if strings.HasPrefix(line, "## ") {
			sections = append(sections, section{version: strings.TrimSpace(strings.TrimPrefix(line, "## "))})
			continue
		}
		if linkReference.MatchString(line) {
			continue
		}
		if len(sections) > 0 {
			if strings.HasPrefix(line, "### ") {
				line = "**" + strings.TrimSpace(strings.TrimPrefix(line, "### ")) + "**"
			}
			sections[len(sections)-1].body = append(sections[len(sections)-1].body, line)
		}
	}
	if len(sections) == 0 {
		return "", fmt.Errorf("CHANGELOG.md has no ## sections")
	}
	pick := sections[0]
	for _, s := range sections {
		if !strings.EqualFold(s.version, "Unreleased") {
			pick = s
			break
		}
	}
	var heading string
	if strings.EqualFold(pick.version, "Unreleased") {
		heading = "**Not released yet** · changes on `main`"
	} else {
		heading = "**v" + strings.TrimPrefix(pick.version, "v") + "**"
		if pick.date != "" {
			heading += " · " + pick.date
		}
		if pick.yanked {
			heading += " · yanked"
		}
	}
	return heading + "\n\n" + strings.TrimSpace(strings.Join(pick.body, "\n")), nil
}

// Render regenerates every generated section of readmeDoc.
func Render(readmeDoc, changelog string, services []catalog.Service) (string, error) {
	doc, err := ReplaceSection(readmeDoc, "services", ServicesTable(services))
	if err != nil {
		return "", err
	}
	news, err := LatestChanges(changelog)
	if err != nil {
		return "", err
	}
	return ReplaceSection(doc, "whats-new", news)
}
