package menubar

import (
	"testing"

	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

// Windows cannot count blocks yet, so its today line never says "no blocks":
// it shows only the VPN drops, and nothing when the VPN never dropped.
func TestTodayLineOnWindowsLeavesOutBlocks(t *testing.T) {
	en, es := English.ForOS("windows"), Spanish.ForOS("windows")
	cases := []struct {
		l    Lang
		s    ipc.Stats
		want string
	}{
		{en, ipc.Stats{TodayDrops: 2}, "Today: VPN dropped 2 times"},
		{es, ipc.Stats{TodayDrops: 1}, "Hoy: la VPN se cayó 1 vez"},
		{es, ipc.Stats{TodayDrops: 3}, "Hoy: la VPN se cayó 3 veces"},
		{en, ipc.Stats{TodayBlocks: 7, TodayDrops: 2}, "Today: VPN dropped 2 times"},
		{en, ipc.Stats{}, ""},
		{es, ipc.Stats{TodayBlocks: 7}, ""},
	}
	for _, c := range cases {
		if got := todayLine(c.l, c.s); got != c.want {
			t.Errorf("todayLine(%v, %+v) = %q, want %q", c.l, c.s, got, c.want)
		}
	}
}

// macOS and Linux keep counting blocks.
func TestTodayLineElsewhereKeepsBlocks(t *testing.T) {
	cases := []struct {
		l    Lang
		s    ipc.Stats
		want string
	}{
		{English, ipc.Stats{}, "Today: no blocks"},
		{English.ForOS("linux"), ipc.Stats{TodayBlocks: 14, TodayDrops: 2}, "Today: 14 blocks · VPN dropped 2 times"},
		{Spanish.ForOS("darwin"), ipc.Stats{TodayBlocks: 1}, "Hoy: 1 bloqueo"},
	}
	for _, c := range cases {
		if got := todayLine(c.l, c.s); got != c.want {
			t.Errorf("todayLine(%v, %+v) = %q, want %q", c.l, c.s, got, c.want)
		}
	}
}
