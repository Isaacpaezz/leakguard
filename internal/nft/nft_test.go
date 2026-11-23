package nft

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
)

var _ firewall.Firewall = Firewall{}

// Nested and touching ranges merge into one interval per family.
var services = []catalog.Service{
	{ID: "claude", IPv4: []string{"160.79.104.0/23", "160.79.104.0/24"}, IPv6: []string{"2607:6bc0::/48"}},
	{ID: "openai", IPv4: []string{"160.79.106.0/24"}, IPv6: []string{"2607:6bc0:1::/48"}},
}

const (
	elems4 = `{"range": ["160.79.104.0", "160.79.106.255"]}`
	elems6 = `{"prefix": {"addr": "2607:6bc0::", "len": 47}}`
)

const listCmd = "-j list table inet leakguard"

type fakeRunner struct {
	outputs map[string]string
	fail    map[string]error
	calls   []string
	stdin   []string
}

func (f *fakeRunner) Run(stdin string, args ...string) (string, error) {
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	f.stdin = append(f.stdin, stdin)
	if err := f.fail[key]; err != nil {
		return "", err
	}
	return f.outputs[key], nil
}

// listing renders "nft -j list table inet leakguard" as nft 1.1 prints it.
// oif "" means rules that allow no interface; rules false is a flushed chain.
func listing(oif, s4, s6 string, rules bool, packets ...int) string {
	var objs []string
	objs = append(objs, `{"metainfo": {"version": "1.1.3", "json_schema_version": 1}}`,
		`{"table": {"family": "inet", "name": "leakguard", "handle": 2}}`,
		`{"chain": {"family": "inet", "table": "leakguard", "name": "output", "handle": 1, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}}`,
		fmt.Sprintf(`{"set": {"family": "inet", "name": "protected4", "table": "leakguard", "type": "ipv4_addr", "flags": ["interval"], "elem": [%s]}}`, s4),
		fmt.Sprintf(`{"set": {"family": "inet", "name": "protected6", "table": "leakguard", "type": "ipv6_addr", "flags": ["interval"], "elem": [%s]}}`, s6))
	if rules {
		i := 0
		for _, fam := range [][2]string{{"ip", "protected4"}, {"ip6", "protected6"}} {
			for _, tcp := range []bool{true, false} {
				var e []string
				if oif != "" {
					e = append(e, fmt.Sprintf(`{"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": %q}}`, oif))
				}
				e = append(e, fmt.Sprintf(`{"match": {"op": "==", "left": {"payload": {"protocol": %q, "field": "daddr"}}, "right": "@%s"}}`, fam[0], fam[1]))
				reject := `{"reject": {"type": "icmpx", "expr": "port-unreachable"}}`
				if tcp {
					e = append(e, `{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}}`)
					reject = `{"reject": {"type": "tcp reset"}}`
				}
				n := 0
				if i < len(packets) {
					n = packets[i]
				}
				i++
				e = append(e, fmt.Sprintf(`{"counter": {"packets": %d, "bytes": 0}}`, n), reject)
				objs = append(objs, fmt.Sprintf(`{"rule": {"family": "inet", "table": "leakguard", "chain": "output", "expr": [%s]}}`, strings.Join(e, ", ")))
			}
		}
	}
	return `{"nftables": [` + strings.Join(objs, ", ") + "]}"
}

func loaded(oif string) *fakeRunner {
	return &fakeRunner{outputs: map[string]string{listCmd: listing(oif, elems4, elems6, true)}}
}

func acceptAll(string) error { return nil }

func refuse(name string) error {
	if strings.HasPrefix(name, "eth") {
		return fmt.Errorf("%s is not a VPN interface", name)
	}
	return nil
}

var errMissing = errors.New("nft -j list table inet leakguard: exit status 1: Error: No such file or directory")

func TestFindLooksOnlyAtTheSystemPaths(t *testing.T) {
	var asked []string
	got, err := Find(func(p string) bool { asked = append(asked, p); return p == "/usr/bin/nft" })
	if err != nil || got != "/usr/bin/nft" || strings.Join(asked, " ") != "/usr/sbin/nft /sbin/nft /usr/bin/nft" {
		t.Fatalf("Find() = %q, %v; asked %v", got, err, asked)
	}
	_, err = Find(func(string) bool { return false })
	if err == nil || !strings.Contains(err.Error(), "install the nftables package") {
		t.Fatalf("Find() = %v, want the install hint", err)
	}
}

func TestName(t *testing.T) {
	if got := (Firewall{}).Name(); got != "nftables" {
		t.Fatalf("Name() = %q", got)
	}
}

func TestApplyLoadsOneAtomicScriptAndVerifies(t *testing.T) {
	r := loaded("wg-mullvad")
	if err := (Firewall{Runner: r, Check: acceptAll}).Apply("wg-mullvad", services); err != nil {
		t.Fatalf("Apply() = %v", err)
	}
	if got := strings.Join(r.calls, "|"); got != "-f -|"+listCmd {
		t.Fatalf("calls = %s", got)
	}
	want := `table inet leakguard {}
delete table inet leakguard
table inet leakguard {
	set protected4 {
		type ipv4_addr; flags interval;
		elements = { 160.79.104.0-160.79.106.255 }
	}
	set protected6 {
		type ipv6_addr; flags interval;
		elements = { 2607:6bc0::/47 }
	}
	chain output {
		type filter hook output priority filter; policy accept;
		oifname != "wg-mullvad" ip daddr @protected4 meta l4proto tcp counter reject with tcp reset
		oifname != "wg-mullvad" ip daddr @protected4 counter reject with icmpx type port-unreachable
		oifname != "wg-mullvad" ip6 daddr @protected6 meta l4proto tcp counter reject with tcp reset
		oifname != "wg-mullvad" ip6 daddr @protected6 counter reject with icmpx type port-unreachable
	}
}
`
	if r.stdin[0] != want {
		t.Fatalf("script =\n%s\nwant\n%s", r.stdin[0], want)
	}
}

func TestApplyLoadErrorIsReturned(t *testing.T) {
	r := loaded("wg0")
	r.fail = map[string]error{"-f -": errors.New("nft -f -: Operation not permitted")}
	if err := (Firewall{Runner: r, Check: acceptAll}).Apply("wg0", services); err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("Apply() = %v", err)
	}
}

// S7: a refused VPN interface loads rules that allow no interface.
func TestApplyRefusedVPNBlocksEveryInterface(t *testing.T) {
	for _, vpn := range []string{"eth0", `wg0" accept #`} {
		r := loaded("")
		err := (Firewall{Runner: r, Check: refuse}).Apply(vpn, services)
		if err == nil || !strings.Contains(err.Error(), "blocked on every interface") {
			t.Fatalf("Apply(%q) = %v, want refusal", vpn, err)
		}
		if len(r.stdin) == 0 || strings.Contains(r.stdin[0], "oifname") || !strings.Contains(r.stdin[0], "ip6 daddr @protected6 counter reject") {
			t.Fatalf("Apply(%q) script = %q, want block-all rules", vpn, r.stdin)
		}
	}
	err := (Firewall{Runner: loaded(""), Check: refuse}).Apply("eth0", services)
	if err == nil || !strings.Contains(err.Error(), "eth0 is not a VPN interface") {
		t.Fatalf("Apply() = %v, want the checker's reason", err)
	}
}

func TestVerify(t *testing.T) {
	fw := func(r *fakeRunner) Firewall { return Firewall{Runner: r, Check: refuse} }
	if err := fw(loaded("wg0")).Verify("wg0", services); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	// nft may print the merged set as other, equivalent elements.
	split := loaded("wg0")
	split.outputs[listCmd] = listing("wg0", `{"prefix": {"addr": "160.79.104.0", "len": 23}}, {"range": ["160.79.106.0", "160.79.106.255"]}`,
		`{"elem": {"val": {"prefix": {"addr": "2607:6bc0::", "len": 48}}}}, {"prefix": {"addr": "2607:6bc0:1::", "len": 48}}`, true)
	if err := fw(split).Verify("wg0", services); err != nil {
		t.Fatalf("Verify(split elements) = %v", err)
	}
	missing := &fakeRunner{fail: map[string]error{listCmd: errMissing}}
	if err := fw(missing).Verify("wg0", services); !errors.Is(err, firewall.ErrNotLoaded) {
		t.Fatalf("Verify(no table) = %v, want ErrNotLoaded", err)
	}
	acceptRule := strings.TrimSuffix(listing("wg0", elems4, elems6, true), "]}") +
		`, {"rule": {"family": "inet", "table": "leakguard", "chain": "output", "expr": [{"accept": null}]}}]}`
	cases := map[string]struct {
		r   *fakeRunner
		vpn string
	}{
		"reject rules for protected4 are not loaded":                        {&fakeRunner{outputs: map[string]string{listCmd: listing("wg0", elems4, elems6, false)}}, "wg0"},
		"set protected4 does not match":                                     {&fakeRunner{outputs: map[string]string{listCmd: listing("wg0", `{"prefix": {"addr": "160.79.104.0", "len": 23}}`, elems6, true)}}, "wg0"},
		"set protected6 does not match":                                     {&fakeRunner{outputs: map[string]string{listCmd: listing("wg0", elems4, ``, true)}}, "wg0"},
		`rules allow "eth0", which is refused: eth0 is not a VPN interface`: {loaded("eth0"), "eth0"},
		`rules allow "wg0", not "wg1"`:                                      {loaded("wg0"), "wg1"},
		`rules allow no interface, not "wg0"`:                               {loaded(""), "wg0"},
		"blocked on every interface: eth0 is not a VPN interface":           {loaded(""), "eth0"},
		"chain output has 1 unexpected rules":                               {&fakeRunner{outputs: map[string]string{listCmd: acceptRule}}, "wg0"},
	}
	for want, c := range cases {
		if err := fw(c.r).Verify(c.vpn, services); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Verify(%q) = %v, want %q", c.vpn, err, want)
		}
	}
	other := loaded("wg0")
	other.fail = map[string]error{listCmd: errors.New("nft: Operation not permitted")}
	if err := fw(other).Verify("wg0", services); err == nil || errors.Is(err, firewall.ErrNotLoaded) {
		t.Fatalf("Verify() = %v, want the nft error", err)
	}
}

func TestFlushDeletesTheTableEvenWhenAbsent(t *testing.T) {
	r := &fakeRunner{}
	if err := (Firewall{Runner: r}).Flush(); err != nil {
		t.Fatalf("Flush() = %v", err)
	}
	if strings.Join(r.calls, "|") != "-f -" || r.stdin[0] != "table inet leakguard {}\ndelete table inet leakguard\n" {
		t.Fatalf("calls = %v, stdin = %q", r.calls, r.stdin)
	}
}

func TestEnabledAsksNft(t *testing.T) {
	r := &fakeRunner{}
	if on, err := (Firewall{Runner: r}).Enabled(); !on || err != nil || r.calls[0] != "list tables" {
		t.Fatalf("Enabled() = %v, %v; calls %v", on, err, r.calls)
	}
	r.fail = map[string]error{"list tables": errors.New("nft: Operation not supported")}
	if on, err := (Firewall{Runner: r}).Enabled(); on || err == nil {
		t.Fatalf("Enabled() = %v, %v", on, err)
	}
}

func TestBlockCountSumsTheRejectRules(t *testing.T) {
	r := &fakeRunner{outputs: map[string]string{listCmd: listing("wg0", elems4, elems6, true, 3, 1, 5, 2)}}
	if n, err := (Firewall{Runner: r}).BlockCount(); n != 11 || err != nil {
		t.Fatalf("BlockCount() = %d, %v", n, err)
	}
	r.outputs[listCmd] = listing("wg0", elems4, elems6, false)
	if _, err := (Firewall{Runner: r}).BlockCount(); err == nil || errors.Is(err, firewall.ErrNotLoaded) {
		t.Fatalf("BlockCount(no rules) = %v, want an error", err)
	}
	r.outputs[listCmd] = "not json"
	if _, err := (Firewall{Runner: r}).BlockCount(); err == nil {
		t.Fatal("BlockCount(garbage) = nil error")
	}
	r.fail = map[string]error{listCmd: errMissing}
	if _, err := (Firewall{Runner: r}).BlockCount(); !errors.Is(err, firewall.ErrNotLoaded) {
		t.Fatalf("BlockCount(no table) = %v, want ErrNotLoaded", err)
	}
}

// S7: an empty VPN means no interface may carry protected traffic. Apply("")
// loads the block-all rules and verifies them; Verify("") accepts only them.
func TestEmptyVPNBlocksEveryInterface(t *testing.T) {
	r := loaded("")
	if err := (Firewall{Runner: r, Check: refuse}).Apply("", services); err != nil {
		t.Fatalf("Apply(\"\") = %v", err)
	}
	if got := strings.Join(r.calls, "|"); got != "-f -|"+listCmd {
		t.Fatalf("calls = %s", got)
	}
	if strings.Contains(r.stdin[0], "oifname") || !strings.Contains(r.stdin[0], "ip6 daddr @protected6 counter reject") {
		t.Fatalf("script = %q, want block-all rules", r.stdin[0])
	}
	if err := (Firewall{Runner: loaded(""), Check: refuse}).Verify("", services); err != nil {
		t.Fatalf("Verify(\"\") = %v", err)
	}
	err := (Firewall{Runner: loaded("wg0"), Check: refuse}).Verify("", services)
	if err == nil || !strings.Contains(err.Error(), `rules allow "wg0"; they should block protected services on every interface`) {
		t.Fatalf("Verify(\"\") with wg0 allowed = %v", err)
	}
	missing := &fakeRunner{fail: map[string]error{listCmd: errMissing}}
	if err := (Firewall{Runner: missing, Check: refuse}).Verify("", services); !errors.Is(err, firewall.ErrNotLoaded) {
		t.Fatalf("Verify(\"\") without a table = %v, want ErrNotLoaded", err)
	}
	bad := loaded("")
	bad.fail = map[string]error{"-f -": errors.New("nft -f -: Operation not permitted")}
	if err := (Firewall{Runner: bad, Check: refuse}).Apply("", services); err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("Apply(\"\") with a failed load = %v", err)
	}
}
