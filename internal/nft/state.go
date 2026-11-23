package nft

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
)

// state is what "nft -j list table inet leakguard" reports.
type state struct {
	sets       map[string][]interval
	rules      []rule
	hooks      map[string]string // chain name -> hook
	unexpected map[string]int    // chain name -> rules that are not leakguard reject rules
}

// rule is one reject rule of chain: traffic to set, TCP only or not, exempt
// on oif ("" exempts no interface).
type rule struct {
	chain, oif, set string
	tcp             bool
	packets         uint64
}

func parseState(out string) (state, error) {
	var doc struct {
		Nftables []struct {
			Chain *struct{ Name, Hook string }
			Set   *struct {
				Name string
				Elem []json.RawMessage
			}
			Rule *struct {
				Chain string
				Expr  []map[string]json.RawMessage
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return state{}, fmt.Errorf("cannot read the nftables rules: %v", err)
	}
	st := state{sets: map[string][]interval{}, hooks: map[string]string{}, unexpected: map[string]int{}}
	for _, o := range doc.Nftables {
		switch {
		case o.Chain != nil:
			st.hooks[o.Chain.Name] = o.Chain.Hook
		case o.Set != nil:
			var ivs []interval
			for _, e := range o.Set.Elem {
				iv, err := parseElem(e)
				if err != nil {
					return state{}, fmt.Errorf("cannot read set %s: %v", o.Set.Name, err)
				}
				ivs = append(ivs, iv)
			}
			st.sets[o.Set.Name] = merge(ivs)
		case o.Rule != nil:
			if r, ok := parseRule(o.Rule.Expr); ok && (o.Rule.Chain == Chain || o.Rule.Chain == ForwardChain) {
				r.chain = o.Rule.Chain
				st.rules = append(st.rules, r)
			} else {
				st.unexpected[o.Rule.Chain]++
			}
		}
	}
	return st, nil
}

// parseElem reads a set element: an address, {"prefix"}, {"range"} or an
// {"elem"} wrapper.
func parseElem(raw json.RawMessage) (interval, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		a, err := netip.ParseAddr(s)
		return interval{a, a}, err
	}
	var e struct {
		Prefix *struct {
			Addr string
			Len  int
		}
		Range []string
		Elem  *struct{ Val json.RawMessage }
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return interval{}, err
	}
	switch {
	case e.Prefix != nil:
		a, err := netip.ParseAddr(e.Prefix.Addr)
		if err != nil {
			return interval{}, err
		}
		p := netip.PrefixFrom(a, e.Prefix.Len)
		if !p.IsValid() {
			return interval{}, fmt.Errorf("bad prefix %s/%d", e.Prefix.Addr, e.Prefix.Len)
		}
		return interval{p.Masked().Addr(), lastAddr(p)}, nil
	case len(e.Range) == 2:
		lo, err1 := netip.ParseAddr(e.Range[0])
		hi, err2 := netip.ParseAddr(e.Range[1])
		if err1 != nil || err2 != nil || hi.Less(lo) {
			return interval{}, fmt.Errorf("bad range %v", e.Range)
		}
		return interval{lo, hi}, nil
	case e.Elem != nil:
		return parseElem(e.Elem.Val)
	}
	return interval{}, fmt.Errorf("unknown element %s", raw)
}

type match struct {
	Op   string
	Left struct {
		Meta, Payload *struct{ Key, Protocol, Field string }
	}
	Right json.RawMessage
}

// isTCP reports whether the right side of a meta l4proto match is TCP:
// nft 1.1 prints "tcp", nft 1.0.x prints the protocol number 6.
func isTCP(raw json.RawMessage) bool {
	var name string
	if json.Unmarshal(raw, &name) == nil {
		return name == "tcp"
	}
	var n int
	return json.Unmarshal(raw, &n) == nil && n == 6
}

// parseRule reads [oifname != X] {ip|ip6} daddr @set [meta l4proto tcp]
// counter reject; anything else is not a leakguard rule.
func parseRule(exprs []map[string]json.RawMessage) (rule, bool) {
	var r rule
	var counted, rejected bool
	for _, e := range exprs {
		if len(e) != 1 || rejected {
			return rule{}, false
		}
		switch {
		case e["match"] != nil:
			var m match
			if json.Unmarshal(e["match"], &m) != nil || counted {
				return rule{}, false
			}
			meta, pl := m.Left.Meta, m.Left.Payload
			if meta != nil && meta.Key == "l4proto" && m.Op == "==" && isTCP(m.Right) && r.set != "" && !r.tcp {
				r.tcp = true
				continue
			}
			var right string
			if json.Unmarshal(m.Right, &right) != nil {
				return rule{}, false
			}
			switch {
			case meta != nil && meta.Key == "oifname" && m.Op == "!=" && r.oif == "" && r.set == "":
				r.oif = right
			case pl != nil && pl.Field == "daddr" && m.Op == "==" && r.set == "" &&
				(pl.Protocol == "ip" && right == "@"+set4 || pl.Protocol == "ip6" && right == "@"+set6):
				r.set = right[1:]
			default:
				return rule{}, false
			}
		case e["counter"] != nil:
			var c struct{ Packets uint64 }
			if counted || json.Unmarshal(e["counter"], &c) != nil {
				return rule{}, false
			}
			counted, r.packets = true, c.Packets
		case e["reject"] != nil:
			var rj struct{ Type string }
			if !counted || json.Unmarshal(e["reject"], &rj) != nil || r.tcp != (rj.Type == "tcp reset") {
				return rule{}, false
			}
			rejected = true
		default:
			return rule{}, false
		}
	}
	return r, rejected && r.set != ""
}

// allowed returns the one interface the reject rules exempt ("" for none),
// or why the rules are not leakguard's: both chains must sit on their hooks
// and hold every reject rule, all exempting the same interface, and no
// chain of the table may hold anything else.
func (st state) allowed() (string, error) {
	for _, c := range chains {
		if st.hooks[c.name] != c.hook {
			return "", fmt.Errorf("chain %s is not loaded", c.name)
		}
	}
	// leakguard's chains first, then any other, by name.
	names := make([]string, 0, len(st.unexpected))
	for name := range st.unexpected {
		names = append(names, name)
	}
	rank := func(name string) int {
		for i, c := range chains {
			if c.name == name {
				return i
			}
		}
		return len(chains)
	}
	sort.Slice(names, func(i, j int) bool {
		if ri, rj := rank(names[i]), rank(names[j]); ri != rj {
			return ri < rj
		}
		return names[i] < names[j]
	})
	if len(names) > 0 {
		return "", fmt.Errorf("chain %s has %d unexpected rules", names[0], st.unexpected[names[0]])
	}
	have := map[rule]bool{}
	for _, r := range st.rules {
		if r.oif != st.rules[0].oif {
			return "", fmt.Errorf("reject rules allow different interfaces: %q and %q", st.rules[0].oif, r.oif)
		}
		have[rule{chain: r.chain, set: r.set, tcp: r.tcp}] = true
	}
	for _, c := range chains {
		for _, s := range []string{set4, set6} {
			if !have[rule{chain: c.name, set: s, tcp: true}] || !have[rule{chain: c.name, set: s}] {
				return "", fmt.Errorf("reject rules for %s are not loaded in chain %s", s, c.name)
			}
		}
	}
	return st.rules[0].oif, nil
}
