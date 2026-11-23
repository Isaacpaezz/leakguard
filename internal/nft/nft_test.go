package nft

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/catalog"
	"github.com/Isaacpaezz/leakguard/internal/config"
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

// listing renders "nft -j list table inet leakguard" as nft 1.1 prints it:
// the output and forward chains with the same reject rules. oif "" means
// rules that allow no interface; rules false is a table with both chains
// flushed. packets fill the counters in order, output chain first.
func listing(oif, s4, s6 string, rules bool, packets ...int) string {
	objs := header(s4, s6, Chain, ForwardChain)
	if rules {
		objs = append(objs, chainRules(Chain, oif, packets...)...)
		if len(packets) > 4 {
			packets = packets[4:]
		} else {
			packets = nil
		}
		objs = append(objs, chainRules(ForwardChain, oif, packets...)...)
	}
	return document(objs)
}

// header renders the table, the given chains (hooked where their name says)
// and the two sets.
func header(s4, s6 string, chains ...string) []string {
	objs := []string{`{"metainfo": {"version": "1.1.3", "json_schema_version": 1}}`,
		`{"table": {"family": "inet", "name": "leakguard", "handle": 2}}`}
	for i, c := range chains {
		objs = append(objs, fmt.Sprintf(`{"chain": {"family": "inet", "table": "leakguard", "name": %q, "handle": %d, "type": "filter", "hook": %q, "prio": 0, "policy": "accept"}}`, c, i+1, c))
	}
	return append(objs,
		fmt.Sprintf(`{"set": {"family": "inet", "name": "protected4", "table": "leakguard", "type": "ipv4_addr", "flags": ["interval"], "elem": [%s]}}`, s4),
		fmt.Sprintf(`{"set": {"family": "inet", "name": "protected6", "table": "leakguard", "type": "ipv6_addr", "flags": ["interval"], "elem": [%s]}}`, s6))
}

// chainRules renders the four reject rules of chain, exempting oif.
func chainRules(chain, oif string, packets ...int) []string {
	var objs []string
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
			objs = append(objs, fmt.Sprintf(`{"rule": {"family": "inet", "table": "leakguard", "chain": %q, "expr": [%s]}}`, chain, strings.Join(e, ", ")))
		}
	}
	return objs
}

func document(objs []string) string {
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
	chain forward {
		type filter hook forward priority filter; policy accept;
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
	// Output chain 3+1+5+2, forward chain 4+0+0+1.
	r := &fakeRunner{outputs: map[string]string{listCmd: listing("wg0", elems4, elems6, true, 3, 1, 5, 2, 4, 0, 0, 1)}}
	if n, err := (Firewall{Runner: r}).BlockCount(); n != 16 || err != nil {
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

// S7: an accept rule inside the leakguard chain, anywhere, would let
// protected traffic out of the real connection before the reject rules
// see it. Verify, Apply and BlockCount refuse such a chain, also for the
// block-all rules.
func TestAcceptRuleInTheChainFailsVerify(t *testing.T) {
	const chain = `{"chain": {"family": "inet", "table": "leakguard", "name": "output", "handle": 1, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}}`
	accepts := map[string]string{
		"daddr accept": `{"rule": {"family": "inet", "table": "leakguard", "chain": "output", "expr": [` +
			`{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "@protected4"}}, {"accept": null}]}}`,
		"oifname accept": `{"rule": {"family": "inet", "table": "leakguard", "chain": "output", "expr": [` +
			`{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "eth0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}`,
	}
	for name, accept := range accepts {
		for _, vpn := range []string{"wg0", ""} {
			// Inserted first, so it runs before every reject rule.
			out := strings.Replace(listing(vpn, elems4, elems6, true), chain, chain+", "+accept, 1)
			const want = "chain output has 1 unexpected rules"
			fw := Firewall{Runner: &fakeRunner{outputs: map[string]string{listCmd: out}}, Check: refuse}
			if err := fw.Verify(vpn, services); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s, vpn %q: Verify() = %v, want %q", name, vpn, err, want)
			}
			if err := fw.Apply(vpn, services); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s, vpn %q: Apply() = %v, want %q", name, vpn, err, want)
			}
			if _, err := fw.BlockCount(); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s, vpn %q: BlockCount() = %v, want %q", name, vpn, err, want)
			}
		}
	}
}

// nft 1.0.x (Debian 12, Ubuntu 22.04 and 24.04) prints "meta l4proto tcp"
// as the protocol number 6; nft 1.1 prints "tcp". Both are leakguard's
// rules. Any other number (17 is UDP) is not.
func TestVerifyReadsTheProtocolNumberOfOlderNft(t *testing.T) {
	const tcpName = `"left": {"meta": {"key": "l4proto"}}, "right": "tcp"}`
	for _, vpn := range []string{"wg0", ""} {
		old := strings.ReplaceAll(listing(vpn, elems4, elems6, true, 3, 1, 5, 2), tcpName, `"left": {"meta": {"key": "l4proto"}}, "right": 6}`)
		if !strings.Contains(old, `"right": 6}`) {
			t.Fatal("listing has no l4proto match to rewrite")
		}
		fw := Firewall{Runner: &fakeRunner{outputs: map[string]string{listCmd: old}}, Check: refuse}
		if err := fw.Verify(vpn, services); err != nil {
			t.Errorf("Verify(%q) with l4proto 6 = %v", vpn, err)
		}
		if n, err := fw.BlockCount(); n != 11 || err != nil {
			t.Errorf("BlockCount(%q) with l4proto 6 = %d, %v", vpn, n, err)
		}
		udp := strings.ReplaceAll(old, `"right": 6}`, `"right": 17}`)
		fw = Firewall{Runner: &fakeRunner{outputs: map[string]string{listCmd: udp}}, Check: refuse}
		if err := fw.Verify(vpn, services); err == nil || !strings.Contains(err.Error(), "chain output has 2 unexpected rules") {
			t.Errorf("Verify(%q) with l4proto 17 = %v, want unexpected rules", vpn, err)
		}
	}
}

// S7: traffic this computer forwards for containers and virtual machines
// (rootful Docker, libvirt NAT) passes the forward hook, not the output
// hook. Both chains carry the same reject rules, for a named VPN and for
// the block-all rules alike.
func TestScriptRejectsForwardedTrafficToo(t *testing.T) {
	for _, vpn := range []string{"wg0", ""} {
		script, err := Script(vpn, services)
		if err != nil {
			t.Fatalf("Script(%q) = %v", vpn, err)
		}
		out := strings.Index(script, "\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n")
		fwd := strings.Index(script, "\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n")
		if out < 0 || fwd < 0 {
			t.Fatalf("Script(%q) lacks the output or forward chain:\n%s", vpn, script)
		}
		body := func(from int) string {
			b := script[from:]
			b = b[strings.Index(b, "accept;\n")+len("accept;\n"):]
			return b[:strings.Index(b, "\t}\n")]
		}
		if body(out) != body(fwd) || strings.Count(body(fwd), "counter reject") != 4 {
			t.Fatalf("Script(%q): forward rules\n%s\ndiffer from output rules\n%s", vpn, body(fwd), body(out))
		}
		if strings.Contains(body(fwd), "oifname") != (vpn != "") {
			t.Fatalf("Script(%q) forward rules = %s", vpn, body(fwd))
		}
	}
}

// S7: Verify (and so Apply, status and the daemon's check) accepts only a
// table whose forward chain is as strict as its output chain.
func TestVerifyNeedsTheForwardChain(t *testing.T) {
	fw := func(out string) Firewall {
		return Firewall{Runner: &fakeRunner{outputs: map[string]string{listCmd: out}}, Check: refuse}
	}
	extra := `{"rule": {"family": "inet", "table": "leakguard", "chain": "forward", "expr": [{"accept": null}]}}`
	cases := map[string]struct {
		out, vpn, want string
	}{
		"no forward chain": {document(append(header(elems4, elems6, Chain), chainRules(Chain, "wg0")...)), "wg0",
			"chain forward is not loaded"},
		"forward chain on the output hook": {strings.Replace(listing("wg0", elems4, elems6, true), `"name": "forward", "handle": 2, "type": "filter", "hook": "forward"`, `"name": "forward", "handle": 2, "type": "filter", "hook": "output"`, 1), "wg0",
			"chain forward is not loaded"},
		"flushed forward chain": {document(append(header(elems4, elems6, Chain, ForwardChain), chainRules(Chain, "wg0")...)), "wg0",
			"reject rules for protected4 are not loaded in chain forward"},
		"forward chain exempts another interface": {document(append(append(header(elems4, elems6, Chain, ForwardChain), chainRules(Chain, "wg0")...), chainRules(ForwardChain, "eth0")...)), "wg0",
			`reject rules allow different interfaces: "wg0" and "eth0"`},
		"forward chain exempts an interface in block-all rules": {document(append(append(header(elems4, elems6, Chain, ForwardChain), chainRules(Chain, "")...), chainRules(ForwardChain, "docker0")...)), "",
			`reject rules allow different interfaces: "" and "docker0"`},
		"accept rule in the forward chain": {strings.TrimSuffix(listing("wg0", elems4, elems6, true), "]}") + ", " + extra + "]}", "wg0",
			"chain forward has 1 unexpected rules"},
	}
	for name, c := range cases {
		f := fw(c.out)
		if err := f.Verify(c.vpn, services); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Verify(%q) = %v, want %q", name, c.vpn, err, c.want)
		}
		if err := f.Apply(c.vpn, services); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Apply(%q) = %v, want %q", name, c.vpn, err, c.want)
		}
		if _, err := f.BlockCount(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: BlockCount() = %v, want %q", name, err, c.want)
		}
	}
	for _, vpn := range []string{"wg0", ""} {
		if err := fw(listing(vpn, elems4, elems6, true)).Verify(vpn, services); err != nil {
			t.Errorf("Verify(%q) with both chains = %v", vpn, err)
		}
	}
}

// Rules inside one chain that exempt different interfaces are not
// leakguard's: one of them would let protected traffic out elsewhere.
func TestVerifyRefusesRulesThatExemptDifferentInterfaces(t *testing.T) {
	out := listing("wg0", elems4, elems6, true)
	// The second output rule (IPv4, any protocol) exempts wg1 instead.
	i := strings.Index(out, `"right": "wg0"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "@protected4"}}, {"counter"`)
	if i < 0 {
		t.Fatal("listing has no IPv4 rule without the TCP match")
	}
	out = out[:i] + `"right": "wg1"` + out[i+len(`"right": "wg0"`):]
	fw := Firewall{Runner: &fakeRunner{outputs: map[string]string{listCmd: out}}, Check: refuse}
	const want = `reject rules allow different interfaces: "wg0" and "wg1"`
	for _, vpn := range []string{"wg0", "wg1"} {
		if err := fw.Verify(vpn, services); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Verify(%q) = %v, want %q", vpn, err, want)
		}
	}
	if _, err := fw.BlockCount(); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("BlockCount() = %v, want %q", err, want)
	}
}

// S7: without an injected checker, the firewall asks the system's VPN
// rules. A real connection (en0 is one on macOS, and on Linux whether it
// exists or not) and loopback are refused: the loaded rules exempt no
// interface, and the refusal is returned.
func TestNilCheckUsesTheSystemVPNRules(t *testing.T) {
	for _, vpn := range []string{"en0", "lo"} {
		r := loaded("")
		err := (Firewall{Runner: r}).Apply(vpn, services)
		if err == nil || !strings.Contains(err.Error(), "blocked on every interface") || !errors.Is(err, config.ErrVPNRefused) {
			t.Fatalf("Apply(%q) with the system checker = %v, want the refusal", vpn, err)
		}
		if len(r.stdin) != 1 || strings.Contains(r.stdin[0], "oifname") || strings.Count(r.stdin[0], "counter reject") != 8 {
			t.Fatalf("Apply(%q) loaded %q, want block-all rules in both chains", vpn, r.stdin)
		}
		err = (Firewall{Runner: loaded(vpn)}).Verify(vpn, services)
		if err == nil || !strings.Contains(err.Error(), "which is refused") {
			t.Fatalf("Verify(%q) of rules that exempt it = %v, want the refusal", vpn, err)
		}
	}
}

// integrationGate decides whether the privileged integration tests run:
// only with LEAKGUARD_NFT_INTEGRATION=1, and then root and every tool find
// reports are required; a missing one is an error, not a skip.
func integrationGate(env string, euid int, finds ...func() error) (bool, error) {
	if env != "1" {
		return false, nil
	}
	if euid != 0 {
		return false, errors.New("LEAKGUARD_NFT_INTEGRATION=1 needs root")
	}
	for _, find := range finds {
		if err := find(); err != nil {
			return false, err
		}
	}
	return true, nil
}

// S4: the privileged integration tests run only when asked for, and a run
// that asked for them fails, never skips, when it cannot load real rules.
func TestIntegrationGate(t *testing.T) {
	ok := func() error { return nil }
	missing := func() error { return errors.New("nft not found") }
	cases := []struct {
		name string
		env  string
		euid int
		find func() error
		run  bool
		err  string
	}{
		{"not asked", "", 0, ok, false, ""},
		{"not asked, not root", "0", 1000, missing, false, ""},
		{"asked, not root", "1", 1000, ok, false, "LEAKGUARD_NFT_INTEGRATION=1 needs root"},
		{"asked, no nft", "1", 0, missing, false, "nft not found"},
		{"asked, ready", "1", 0, ok, true, ""},
	}
	for _, c := range cases {
		run, err := integrationGate(c.env, c.euid, c.find)
		if run != c.run || (err == nil) != (c.err == "") || err != nil && !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: integrationGate() = %v, %v; want %v, %q", c.name, run, err, c.run, c.err)
		}
	}
}
