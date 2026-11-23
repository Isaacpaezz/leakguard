// Package nft drives the Linux nftables firewall. leakguard owns one table,
// inet leakguard, and replaces it atomically, so other rulesets are never
// edited.
package nft

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

const (
	// Table is the inet table that holds every leakguard rule.
	Table = "leakguard"
	// Chain is the output-hook chain that rejects protected traffic.
	Chain = "output"
	set4  = "protected4"
	set6  = "protected6"
	// replace creates the table if needed and deletes it, so the next
	// definition replaces any old copy in the same transaction.
	replace = "table inet " + Table + " {}\ndelete table inet " + Table + "\n"
)

// Paths are where nft may live; it is never resolved through $PATH.
var Paths = []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"}

// ifName is the Linux interface name syntax. Only such names, quoted, ever
// reach the script, whatever the checker says.
var ifName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

// Find returns the first of Paths that exists.
func Find(exists func(string) bool) (string, error) {
	for _, p := range Paths {
		if exists(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("nft not found at %s; install the nftables package (for example: sudo apt install nftables)", strings.Join(Paths, ", "))
}

// Runner runs nft with the given stdin and arguments.
type Runner interface {
	Run(stdin string, args ...string) (string, error)
}

// ExecRunner runs the real nft.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(stdin string, args ...string) (string, error) {
	path, err := Find(func(p string) bool { _, err := os.Stat(p); return err == nil })
	if err != nil {
		return "", err
	}
	cmd := exec.Command(path, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// Firewall applies and inspects the leakguard table.
type Firewall struct {
	Runner Runner
	// Check reports why a name cannot be the VPN interface; nil means
	// config.CheckVPNInterface.
	Check func(string) error
}

var _ firewall.Firewall = Firewall{}

// Name implements firewall.Firewall.
func (Firewall) Name() string { return "nftables" }

// refusal reports why vpn cannot be allowed in the rules.
func (f Firewall) refusal(vpn string) error {
	if !ifName.MatchString(vpn) {
		return fmt.Errorf("%q is not a valid interface name", vpn)
	}
	if f.Check == nil {
		return config.CheckVPNInterface(vpn)
	}
	return f.Check(vpn)
}

// Script renders the table. Traffic to the services' ranges is rejected
// unless it leaves on vpn; vpn "" rejects it on every interface. TCP gets a
// reset and the rest an ICMP port unreachable, so connects fail at once with
// "connection refused".
func Script(vpn string, services []catalog.Service) (string, error) {
	var cidrs []string
	for _, s := range services {
		cidrs = append(append(cidrs, s.IPv4...), s.IPv6...)
	}
	v4, v6, err := ranges(cidrs)
	if err != nil {
		return "", err
	}
	if vpn != "" && !ifName.MatchString(vpn) {
		return "", fmt.Errorf("%q is not a valid interface name", vpn)
	}
	var b strings.Builder
	b.WriteString(replace)
	fmt.Fprintf(&b, "table inet %s {\n", Table)
	for _, s := range []struct {
		name, typ string
		ivs       []interval
	}{{set4, "ipv4_addr", v4}, {set6, "ipv6_addr", v6}} {
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s; flags interval;\n", s.name, s.typ)
		if len(s.ivs) > 0 {
			elems := make([]string, len(s.ivs))
			for i, iv := range s.ivs {
				elems[i] = iv.String()
			}
			fmt.Fprintf(&b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
		}
		b.WriteString("\t}\n")
	}
	fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook output priority filter; policy accept;\n", Chain)
	oif := ""
	if vpn != "" {
		oif = fmt.Sprintf("oifname != %q ", vpn)
	}
	for _, m := range []string{"ip daddr @" + set4, "ip6 daddr @" + set6} {
		fmt.Fprintf(&b, "\t\t%s%s meta l4proto tcp counter reject with tcp reset\n", oif, m)
		fmt.Fprintf(&b, "\t\t%s%s counter reject with icmpx type port-unreachable\n", oif, m)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

// Apply replaces the table and verifies it. When vpn is refused, it loads
// rules that allow no interface, so protected traffic stays blocked, and
// returns the reason.
func (f Firewall) Apply(vpn string, services []catalog.Service) error {
	refused := f.refusal(vpn)
	allow := vpn
	if refused != nil {
		allow = ""
	}
	script, err := Script(allow, services)
	if err != nil {
		return err
	}
	_, err = f.Runner.Run(script, "-f", "-")
	if refused != nil {
		if err != nil {
			return fmt.Errorf("cannot use %q as the VPN interface (%v), and cannot block protected services: %w", vpn, refused, err)
		}
		return fmt.Errorf("cannot use %q as the VPN interface, protected services are blocked on every interface: %w", vpn, refused)
	}
	if err != nil {
		return err
	}
	return f.Verify(vpn, services)
}

// Flush deletes the table; a missing table is not an error.
func (f Firewall) Flush() error {
	_, err := f.Runner.Run(replace, "-f", "-")
	return err
}

// Enabled reports whether nftables answers.
func (f Firewall) Enabled() (bool, error) {
	if _, err := f.Runner.Run("", "list", "tables"); err != nil {
		return false, err
	}
	return true, nil
}

// ErrNotLoaded means the leakguard table does not exist.
var ErrNotLoaded = firewall.ErrNotLoaded

// Verify checks that the loaded table is what a successful Apply(vpn,
// services) loads: the sets hold exactly the services' ranges and every
// reject rule exempts vpn only, and vpn is still accepted.
func (f Firewall) Verify(vpn string, services []catalog.Service) error {
	st, err := f.state()
	if err != nil {
		return err
	}
	var cidrs []string
	for _, s := range services {
		cidrs = append(append(cidrs, s.IPv4...), s.IPv6...)
	}
	v4, v6, err := ranges(cidrs)
	if err != nil {
		return err
	}
	if !equal(st.sets[set4], v4) {
		return fmt.Errorf("set %s does not match the protected IPv4 ranges", set4)
	}
	if !equal(st.sets[set6], v6) {
		return fmt.Errorf("set %s does not match the protected IPv6 ranges", set6)
	}
	oif, err := st.allowed()
	if err != nil {
		return err
	}
	switch refused := f.refusal(vpn); {
	case refused != nil && oif == "":
		return fmt.Errorf("protected services are blocked on every interface: %w", refused)
	case refused != nil:
		return fmt.Errorf("rules allow %q, which is refused: %w", oif, refused)
	case oif == "":
		return fmt.Errorf("rules allow no interface, not %q", vpn)
	case oif != vpn:
		return fmt.Errorf("rules allow %q, not %q", oif, vpn)
	}
	return nil
}

// BlockCount sums the packet counters of the reject rules, which start at
// zero on every load.
func (f Firewall) BlockCount() (uint64, error) {
	st, err := f.state()
	if err != nil {
		return 0, err
	}
	if _, err := st.allowed(); err != nil {
		return 0, err
	}
	var n uint64
	for _, r := range st.rules {
		n += r.packets
	}
	return n, nil
}

// state reads the table; a missing table is ErrNotLoaded.
func (f Firewall) state() (state, error) {
	out, err := f.Runner.Run("", "-j", "list", "table", "inet", Table)
	if err != nil {
		if strings.Contains(err.Error(), "No such file or directory") {
			return state{}, ErrNotLoaded
		}
		return state{}, err
	}
	return parseState(out)
}
