package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/pf"
	"github.com/Isaacpaezz/leakguard/internal/stats"
)

const showTable = "-a " + pf.Anchor + " -t leakguard -T show"

// S4: a slow stats save never delays the next verify, and shutdown waits for
// a save in flight.
func TestServeVerifiesWhileAStatsSaveIsSlow(t *testing.T) {
	h, _ := statefulHarness(t)
	h.env.ApplyEvery = 5 * time.Millisecond
	h.env.SampleEvery = time.Millisecond
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	started := make(chan struct{}, 1)
	var saves atomic.Int32
	h.env.SaveStats = func(path string, st stats.State) error {
		saves.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return stats.Save(path, st)
	}
	s := startServe(t, h)
	t.Cleanup(unblock) // runs before the stop that startServe registered
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("no stats save started")
	}
	before := strings.Count(s.stdout.String(), "Protected through")
	s.waitFor(t, "Protected through", before+3)

	s.cancel()
	select {
	case code := <-s.done:
		s.done <- code
		t.Fatal("serve exited while a stats save was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	if code := s.stop(t); code != 0 {
		t.Fatalf("serve exit code = %d: %s", code, s.stderr.String())
	}
	if saves.Load() < 2 {
		t.Fatalf("saves = %d, want the slow one and the one at shutdown", saves.Load())
	}
	if !exists(h.path(stats.DefaultPath)) {
		t.Fatal("the stats were not saved")
	}
}

// triggerPfctl blocks n packets once, on the first pfctl call after the saved
// VPN became vpn: between the request arriving and the anchor load.
type triggerPfctl struct {
	*statefulPfctl
	h     *harness
	vpn   string
	n     uint64
	fired atomic.Bool
}

func (p *triggerPfctl) Run(stdin string, args ...string) (string, error) {
	if !p.fired.Load() {
		if cfg, err := config.Load(p.h.path(config.DefaultPath)); err == nil && cfg.VPNInterface == p.vpn {
			p.fired.Store(true)
			p.statefulPfctl.block(p.n)
		}
	}
	return p.statefulPfctl.Run(stdin, args...)
}

// S5b: blocks that happen while a set saves the choice are read right before
// the load resets the counter.
func TestServeSetCountsBlocksUpToTheLoad(t *testing.T) {
	h, p := statefulHarness(t)
	h.env.Pfctl = &triggerPfctl{statefulPfctl: p, h: h, vpn: "utun9", n: 5}
	s := startServe(t, h)
	if _, err := s.client.Set("utun9", []string{"anthropic"}); err != nil {
		t.Fatal(err)
	}
	if got := todayBlocks(s); got != 5 {
		t.Fatalf("blocks after a set = %d, want 5", got)
	}
}

// Rule 4: pf turned off is turned back on ("-E") and the rules reloaded.
func TestServeTurnsPfBackOn(t *testing.T) {
	h, p := statefulHarness(t)
	h.env.ApplyEvery = 5 * time.Millisecond
	s := startServe(t, h)
	p.set(func(p *statefulPfctl) { p.disabled = true })
	eventually(t, "pf enabled and a reload", func() bool { return p.count("-E") == 1 && p.count(loadAnchor) >= 2 })
	s.waitFor(t, "Protected through", 3)
	s.stop(t)
	if want := "leakguard: rules not verified, loading them again: pf is disabled; turn it back on with: sudo leakguard apply\n"; !strings.Contains(s.stderr.String(), want) {
		t.Fatalf("stderr = %q, want %q", s.stderr.String(), want)
	}
	if n := p.count("-E"); n != 1 {
		t.Fatalf(`"pfctl -E" ran %d times, want once`, n)
	}
}

// Rule 4: a pfctl error during verify is logged; once pfctl recovers, rules
// that went missing meanwhile are loaded again.
func TestServeReloadsWhenPfctlRecovers(t *testing.T) {
	h, p := statefulHarness(t)
	h.env.ApplyEvery = 5 * time.Millisecond
	s := startServe(t, h)
	p.set(func(p *statefulPfctl) {
		p.fail = map[string]error{"-s info": errors.New("pfctl: device busy")}
		p.rules, p.table, p.packets = nil, nil, 0
	})
	eventually(t, "the error logged", func() bool { return strings.Contains(s.stderr.String(), "pfctl: device busy") })
	p.set(func(p *statefulPfctl) { p.fail = nil })
	eventually(t, "a reload", func() bool { return p.loadedRules() && p.count(loadAnchor) >= 2 })
	s.stop(t)
	if n := p.count(flushAnchor); n != 0 {
		t.Fatalf("the rules were flushed %d times", n)
	}
}

// Rule 4: an invalid saved choice leaves the loaded rules alone; a valid one
// is loaded.
func TestServeKeepsTheRulesOnAnInvalidConfig(t *testing.T) {
	h, p := statefulHarness(t)
	h.env.ApplyEvery = 5 * time.Millisecond
	s := startServe(t, h)
	if err := os.WriteFile(h.path(config.DefaultPath), []byte(`{"vpn_interface": "ipsec0", "services": ["gemini"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the invalid config logged", func() bool {
		return strings.Count(s.stderr.String(), `invalid configuration: unknown service "gemini"`) >= 2
	})
	if !p.loadedRules() || p.count(loadAnchor) != 1 || p.count(flushAnchor) != 0 {
		t.Fatalf("an invalid config touched the rules: loads %d, flushes %d", p.count(loadAnchor), p.count(flushAnchor))
	}
	h.saveConfig(t, config.Config{VPNInterface: "utun9", Services: []string{"anthropic"}})
	s.waitFor(t, "Protected through utun9: anthropic\n", 1)
	s.stop(t)
	if n := p.count(loadAnchor); n != 2 {
		t.Fatalf("loads = %d, want 2", n)
	}
}

// Rule 4: a clock going backwards never stops the reloads.
func TestServeReloadsWhenTheClockGoesBackwards(t *testing.T) {
	h, p := statefulHarness(t)
	h.env.ApplyEvery = 5 * time.Millisecond
	h.env.SampleEvery = time.Millisecond
	var ticks atomic.Int64
	h.env.Now = func() time.Time { return fixedNow.Add(-time.Duration(ticks.Add(1)) * time.Minute) }
	s := startServe(t, h)
	for want := 2; want <= 3; want++ {
		p.unload()
		eventually(t, "a reload", func() bool { return p.loadedRules() && p.count(loadAnchor) >= want })
	}
	if code := s.stop(t); code != 0 {
		t.Fatalf("serve exit code = %d: %s", code, s.stderr.String())
	}
}

// S4: a corrupt stats file is logged and the rules still load at start.
func TestServeLoadsTheRulesWithCorruptStats(t *testing.T) {
	h, p := statefulHarness(t)
	path := h.path(stats.DefaultPath)
	// The stats directory is not the config directory on every OS.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := startServe(t, h)
	if n := p.count(loadAnchor); n != 1 {
		t.Fatalf("loads at start = %d, want 1", n)
	}
	if st, err := s.client.Status(); err != nil || !st.Protected || st.Stats != nil && st.Stats.TodayBlocks != 0 {
		t.Fatalf("Status() = %+v, %v", st, err)
	}
	s.stop(t)
	if !strings.Contains(s.stderr.String(), "leakguard: could not read the session stats: "+path+": ") {
		t.Fatalf("stderr = %q", s.stderr.String())
	}
}

// S5b: a pause whose config save fails flushed the counter; the reload that
// follows never counts a block twice.
func TestServePauseWithAFailedSaveNeverDoubleCounts(t *testing.T) {
	skipUnlessSavesCanFail(t)
	h, p := statefulHarness(t)
	h.env.ApplyEvery = 5 * time.Millisecond
	s := startServe(t, h)
	dir := filepath.Dir(h.path(config.DefaultPath))
	p.block(5)
	unblock := blockConfigSaves(t, dir)
	if _, err := s.client.Pause(); err == nil || !strings.HasPrefix(err.Error(), "could not save the pause: ") {
		t.Fatalf("Pause() = %v", err)
	}
	unblock()
	eventually(t, "a reload", func() bool { return p.loadedRules() && p.count(loadAnchor) >= 2 })
	p.block(2)
	eventually(t, "7 blocks", func() bool { return todayBlocks(s) == 7 })
	s.waitFor(t, "Protected through", strings.Count(s.stdout.String(), "Protected through")+3)
	if got := todayBlocks(s); got != 7 {
		t.Fatalf("blocks = %d, want 7", got)
	}
}

// S5b: reloads whose verification fails reset the counter without the
// daemon knowing it. Blocks may then be lost (a reading equal to the last
// one looks like no change), but never counted twice; blocks read before and
// after are all counted.
func TestServeFailedReloadsNeverOverCount(t *testing.T) {
	h, p := statefulHarness(t)
	h.env.ApplyEvery = 5 * time.Millisecond
	s := startServe(t, h)
	p.block(5)
	eventually(t, "5 blocks", func() bool { return todayBlocks(s) == 5 })
	p.set(func(p *statefulPfctl) {
		p.fail = map[string]error{showTable: errors.New("pfctl: table busy")}
		p.afterLoad = 2
	})
	eventually(t, "failed reloads", func() bool { return p.count(loadAnchor) >= 5 })
	p.set(func(p *statefulPfctl) { p.fail, p.afterLoad = nil, 0 })
	s.waitFor(t, "Protected through", strings.Count(s.stdout.String(), "Protected through")+3)
	got := todayBlocks(s)
	if got < 5 || got > p.blocked() {
		t.Fatalf("blocks = %d, want between 5 and %d", got, p.blocked())
	}
	p.block(4)
	eventually(t, "4 more blocks", func() bool { return todayBlocks(s) == got+4 })
	s.waitFor(t, "Protected through", strings.Count(s.stdout.String(), "Protected through")+3)
	if n := todayBlocks(s); n != got+4 || n > p.blocked() {
		t.Fatalf("blocks = %d, want %d (at most %d)", n, got+4, p.blocked())
	}
}

// Concurrency: requests, 1 ms checks and 1 ms samples never deadlock, and
// serve shuts down cleanly.
func TestServeConcurrentRequestsNeverDeadlock(t *testing.T) {
	h, _ := statefulHarness(t)
	h.env.ApplyEvery = time.Millisecond
	h.env.SampleEvery = time.Millisecond
	s := startServe(t, h)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				switch (i + j) % 3 {
				case 0:
					s.client.Status()
				case 1:
					s.client.Set("ipsec0", []string{"anthropic"})
				default:
					s.client.Pause()
				}
			}
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("requests deadlocked")
	}
	if code := s.stop(t); code != 0 {
		t.Fatalf("serve exit code = %d: %s", code, s.stderr.String())
	}
}
