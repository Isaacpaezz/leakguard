package main

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/firewall"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
	"github.com/Isaacpaezz/leakguard/internal/stats"
)

const (
	// sampleInterval is how often "serve" checks whether the VPN is connected.
	sampleInterval = 5 * time.Second
	// statsSaveInterval bounds how often "serve" writes the stats file.
	statsSaveInterval = time.Minute
)

// daemonStats keeps the session stats of "serve". Stats never change
// protection (fail closed): every failure here is logged once and ignored.
type daemonStats struct {
	c    *cli
	path string

	mu sync.Mutex // guards everything below and the tracker
	// t is nil until load; what happens before is kept in pending, in
	// order, and replayed on the loaded tracker.
	t       *stats.Tracker
	pending []func(*stats.Tracker)
	dirty   bool
	saved   time.Time
	readErr string // the last counter error logged, to log each one once
	// saveFailing is set after a failed save was logged; the next failures
	// are not logged until a save succeeds (each names a new temp file).
	saveFailing bool

	saveMu sync.Mutex // serializes writes of the file
}

func (c *cli) location() *time.Location {
	if c.env.Location != nil {
		return c.env.Location
	}
	return time.Local
}

func (c *cli) statsPath() string { return rooted(c.env.Root, stats.DefaultPath) }

// newStats returns the stats of "serve", not loaded yet: the daemon loads
// its rules first and the saved stats after, so stats file I/O never delays
// protection.
func (c *cli) newStats() *daemonStats {
	return &daemonStats{c: c, path: c.statsPath()}
}

// load reads the saved stats, then replays what happened before; a missing
// or corrupt file starts fresh.
func (d *daemonStats) load() {
	t, err := stats.Load(d.path, d.c.location())
	if err != nil {
		d.logf("could not read the session stats: %v", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, op := range d.pending {
		op(t)
	}
	d.t, d.pending = t, nil
}

// record applies op to the tracker, or keeps it for load. The caller holds
// d.mu.
func (d *daemonStats) record(op func(*stats.Tracker)) {
	d.dirty = true
	if d.t == nil {
		d.pending = append(d.pending, op)
		return
	}
	op(d.t)
}

func (d *daemonStats) logf(format string, a ...any) {
	fmt.Fprintf(d.c.stderr, "%s leakguard: %s\n", d.c.now().Format(time.RFC3339), fmt.Sprintf(format, a...))
}

// countBlocks reads the firewall's block counter into the tracker. The caller holds the
// service lock and calls it right before a reload or flush, so no block is
// lost.
func (d *daemonStats) countBlocks(fw firewall.Firewall) {
	n, err := fw.BlockCount()
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case errors.Is(err, firewall.ErrNotLoaded):
		// No rules, no counter: the reload that follows counts from zero.
	case err != nil:
		if msg := err.Error(); msg != d.readErr {
			d.readErr = msg
			d.logf("could not read the block counter: %v", err)
		}
	default:
		d.readErr = ""
		now := d.c.now()
		d.record(func(t *stats.Tracker) { t.ObserveBlocks(now, n) })
	}
}

// counterReset records that the daemon just loaded or flushed the anchor.
func (d *daemonStats) counterReset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.record((*stats.Tracker).CounterReset)
}

// sampleVPN records whether the saved VPN is connected, and returns it.
// Without a saved VPN, or when the interfaces cannot be listed, there is
// nothing to record and ok is false.
func (d *daemonStats) sampleVPN() (connected, ok bool) {
	cfg, err := config.Load(d.c.configPath())
	if err != nil || cfg.VPNInterface == "" {
		return false, false
	}
	ifs, err := d.c.env.Interfaces()
	if err != nil {
		return false, false
	}
	for _, i := range ifs {
		if i.Name == cfg.VPNInterface {
			connected = i.Connected()
		}
	}
	now := d.c.now()
	d.mu.Lock()
	d.record(func(t *stats.Tracker) { t.ObserveVPN(now, connected) })
	d.mu.Unlock()
	return connected, true
}

// save writes the stats when they changed, at most once per
// statsSaveInterval unless force is set.
func (d *daemonStats) save(force bool) {
	d.saveMu.Lock()
	defer d.saveMu.Unlock()
	d.mu.Lock()
	now := d.c.now()
	if d.t == nil || !d.dirty || (!force && !d.saved.IsZero() && now.Sub(d.saved) < statsSaveInterval) {
		d.mu.Unlock()
		return
	}
	st := d.t.State()
	d.dirty, d.saved = false, now
	d.mu.Unlock()

	save := stats.Save
	if d.c.env.SaveStats != nil {
		save = d.c.env.SaveStats
	}
	err := save(d.path, st)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil {
		d.saveFailing = false
		return
	}
	d.dirty = true
	if !d.saveFailing {
		d.saveFailing = true
		d.logf("could not save the session stats: %v", err)
	}
}

// ipc returns the stats for the status answer, or nil before the load or
// the first VPN sample.
func (d *daemonStats) ipc() *ipc.Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.t == nil {
		return nil
	}
	return ipcStats(d.t.Summary(d.c.now()))
}

// ipcStats is sum as the daemon sends it: nil when the VPN was never
// sampled, and no session start when the last sample is old.
func ipcStats(sum stats.Summary) *ipc.Stats {
	if !sum.Known {
		return nil
	}
	st := &ipc.Stats{
		Connected:       sum.Connected && sum.Fresh,
		TodayVPNSeconds: int64(sum.VPN / time.Second),
		TodayBlocks:     sum.Blocks,
		TodayDrops:      sum.Drops,
		Day:             sum.Day,
	}
	if sum.Fresh {
		st.SessionSince = sum.Since.Format(time.RFC3339)
	}
	return st
}

// printStats writes the "Session:" and "Today:" lines of status.
func printStats(w io.Writer, st *ipc.Stats, now time.Time) {
	if st == nil {
		return
	}
	if since, err := time.Parse(time.RFC3339, st.SessionSince); err == nil {
		state := "disconnected"
		if st.Connected {
			state = "connected"
		}
		fmt.Fprintf(w, "Session:\tVPN %s for %s\n", state, stats.FormatDuration(now.Sub(since)))
	}
	blocks, drops := "no blocks", "VPN never dropped"
	if st.TodayBlocks > 0 {
		blocks = plural(st.TodayBlocks, "block", "blocks")
	}
	if st.TodayDrops > 0 {
		drops = "VPN dropped " + plural(uint64(st.TodayDrops), "time", "times")
	}
	fmt.Fprintf(w, "Today:\t%s · %s · %s on the VPN\n", blocks, drops,
		stats.FormatDuration(time.Duration(st.TodayVPNSeconds)*time.Second))
}

func plural(n uint64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// savedStats reads the stats the daemon saved, for status without the
// daemon. Unreadable stats are simply not shown.
func (c *cli) savedStats() *ipc.Stats {
	t, err := stats.Load(c.statsPath(), c.location())
	if err != nil {
		return nil
	}
	return ipcStats(t.Summary(c.now()))
}
