package nft

import (
	"fmt"
	"net/netip"
	"sort"
)

// interval is an inclusive range of addresses of one family.
type interval struct{ lo, hi netip.Addr }

func (iv interval) String() string {
	for bits := 0; bits <= iv.lo.BitLen(); bits++ {
		if p := netip.PrefixFrom(iv.lo, bits); p.Masked().Addr() == iv.lo && lastAddr(p) == iv.hi {
			if bits == iv.lo.BitLen() {
				return iv.lo.String()
			}
			return p.String()
		}
	}
	return iv.lo.String() + "-" + iv.hi.String()
}

// lastAddr is the highest address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// merge sorts intervals and joins the ones that overlap or touch, so nested
// or overlapping catalog ranges load into an interval set and compare equal
// to what nft prints back.
func merge(in []interval) []interval {
	sort.Slice(in, func(i, j int) bool { return in[i].lo.Less(in[j].lo) })
	var out []interval
	for _, iv := range in {
		if n := len(out); n > 0 {
			last := &out[n-1]
			next := last.hi.Next()
			if !next.IsValid() || !next.Less(iv.lo) {
				if last.hi.Less(iv.hi) {
					last.hi = iv.hi
				}
				continue
			}
		}
		out = append(out, iv)
	}
	return out
}

// ranges returns the merged IPv4 and IPv6 ranges of the given CIDRs.
func ranges(cidrs []string) (v4, v6 []interval, err error) {
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, nil, fmt.Errorf("bad range %q: %v", c, err)
		}
		iv := interval{p.Masked().Addr(), lastAddr(p)}
		if p.Addr().Is4() {
			v4 = append(v4, iv)
		} else {
			v6 = append(v6, iv)
		}
	}
	return merge(v4), merge(v6), nil
}

func equal(a, b []interval) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
