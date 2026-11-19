package main

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/config"
	"github.com/Isaacpaezz/leakguard/internal/ipc"
	"github.com/Isaacpaezz/leakguard/internal/pf"
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

	mu      sync.Mutex // guards everything below and the tracker
	t       *stats.Tracker
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

func (c *cli) statsPath() string { return filepath.Join(c.env.Root, stats.DefaultPath) }

// loadStats reads the saved stats; a missing or corrupt file starts fresh.
func (c *cli) loadStats() *daemonStats {
	t, err := stats.Load(c.statsPath(), c.location())
	d := &daemonStats{c: c, path: c.statsPath(), t: t}
	if err != nil {
		d.logf("could not read the session stats: %v", err)
	}
	return d
}

func (d *daemonStats) logf(format string, a ...any) {
	fmt.Fprintf(d.c.stderr, "%s leakguard: %s\n", d.c.now().Format(time.RFC3339), fmt.Sprintf(format, a...))
}

// countBlocks reads pf's block counter into the tracker. The caller holds the
// service lock, so the reading always comes before a reload or flush.
func (d *daemonStats) countBlocks(fw pf.Firewall) {
	n, err := fw.BlockCount()
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case errors.Is(err, pf.ErrNotLoaded):
		// No rules, no counter: the reload that follows counts from zero.
	case err != nil:
		if msg := err.Error(); msg != d.readErr {
			d.readErr = msg
			d.logf("could not read the block counter: %v", err)
		}
	default:
		d.readErr = ""
		d.t.ObserveBlocks(d.c.now(), n)
		d.dirty = true
	}
}

// counterReset records that the daemon just loaded or flushed the anchor.
func (d *daemonStats) counterReset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.t.CounterReset()
	d.dirty = true
}

// sampleVPN records whether the saved VPN is connected. Without a saved VPN,
// or when the interfaces cannot be listed, there is nothing to record.
func (d *daemonStats) sampleVPN() {
	cfg, err := config.Load(d.c.configPath())
	if err != nil || cfg.VPNInterface == "" {
		return
	}
	ifs, err := d.c.env.Interfaces()
	if err != nil {
		return
	}
	connected := false
	for _, i := range ifs {
		if i.Name == cfg.VPNInterface {
			connected = i.Connected()
		}
	}
	d.mu.Lock()
	d.t.ObserveVPN(d.c.now(), connected)
	d.dirty = true
	d.mu.Unlock()
}

// save writes the stats when they changed, at most once per
// statsSaveInterval unless force is set.
func (d *daemonStats) save(force bool) {
	d.saveMu.Lock()
	defer d.saveMu.Unlock()
	d.mu.Lock()
	now := d.c.now()
	if !d.dirty || (!force && !d.saved.IsZero() && now.Sub(d.saved) < statsSaveInterval) {
		d.mu.Unlock()
		return
	}
	st := d.t.State()
	d.dirty, d.saved = false, now
	d.mu.Unlock()

	err := stats.Save(d.path, st)
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

// ipc returns the stats for the status answer, or nil before the first VPN
// sample.
func (d *daemonStats) ipc() *ipc.Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
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
	fmt.Fprintf(w, "Today:\t%s · VPN dropped %s · %s on the VPN\n",
		plural(st.TodayBlocks, "block", "blocks"), plural(uint64(max(st.TodayDrops, 0)), "time", "times"),
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
