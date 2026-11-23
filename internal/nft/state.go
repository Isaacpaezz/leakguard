package nft

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

// state is what "nft -j list table inet leakguard" reports.
type state struct {
	sets       map[string][]interval
	rules      []rule
	hooked     bool // the output-hook chain exists
	unexpected int  // rules that are not leakguard reject rules
}

// rule is one reject rule: traffic to set, TCP only or not, exempt on oif
// ("" exempts no interface).
type rule struct {
	oif, set string
	tcp      bool
	packets  uint64
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
	st := state{sets: map[string][]interval{}}
	for _, o := range doc.Nftables {
		switch {
		case o.Chain != nil:
			st.hooked = st.hooked || (o.Chain.Name == Chain && o.Chain.Hook == "output")
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
			if r, ok := parseRule(o.Rule.Expr); ok && o.Rule.Chain == Chain {
				st.rules = append(st.rules, r)
			} else {
				st.unexpected++
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
			var right string
			if json.Unmarshal(e["match"], &m) != nil || json.Unmarshal(m.Right, &right) != nil || counted {
				return rule{}, false
			}
			meta, pl := m.Left.Meta, m.Left.Payload
			switch {
			case meta != nil && meta.Key == "oifname" && m.Op == "!=" && r.oif == "" && r.set == "":
				r.oif = right
			case pl != nil && pl.Field == "daddr" && m.Op == "==" && r.set == "" &&
				(pl.Protocol == "ip" && right == "@"+set4 || pl.Protocol == "ip6" && right == "@"+set6):
				r.set = right[1:]
			case meta != nil && meta.Key == "l4proto" && m.Op == "==" && right == "tcp" && r.set != "" && !r.tcp:
				r.tcp = true
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
// or why the rules are not leakguard's.
func (st state) allowed() (string, error) {
	if !st.hooked {
		return "", fmt.Errorf("chain %s is not loaded", Chain)
	}
	if st.unexpected > 0 {
		return "", fmt.Errorf("chain %s has %d unexpected rules", Chain, st.unexpected)
	}
	have := map[rule]bool{}
	for _, r := range st.rules {
		if r.oif != st.rules[0].oif {
			return "", fmt.Errorf("reject rules allow different interfaces: %q and %q", st.rules[0].oif, r.oif)
		}
		have[rule{set: r.set, tcp: r.tcp}] = true
	}
	for _, s := range []string{set4, set6} {
		if !have[rule{set: s, tcp: true}] || !have[rule{set: s}] {
			return "", fmt.Errorf("reject rules for %s are not loaded", s)
		}
	}
	return st.rules[0].oif, nil
}
