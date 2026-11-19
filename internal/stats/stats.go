// Package stats keeps the session numbers the menu and "leakguard status"
// show: how long the VPN has been connected or disconnected, and today's
// time on the VPN, VPN drops and blocks. It is pure: the daemon feeds it
// samples with their time, and it never touches the network or pf.
//
// Blocks come from pf's packet counter of leakguard's block rule, which pf
// resets whenever the anchor is reloaded or flushed. The counting rule, which
// never counts a packet twice:
//
//   - A reading at or above the last one adds the difference.
//   - A reading below the last one means pf reset the counter, so the reading
//     itself is what is new.
//   - CounterReset tells the tracker that the daemon itself just reloaded or
//     flushed the anchor: the next reading counts from zero.
//   - The very first reading of a tracker without a baseline (no saved file)
//     is only a baseline: what the counter holds from before is unknown.
//   - After a daemon restart, the saved last reading is the baseline: the
//     same counter adds its difference; a counter reset meanwhile adds at most
//     the reading. Either way it never adds more than what pf counted since
//     the saved reading.
//
// Blocks between the last reading and a reset that the daemon did not see
// (for example "sudo leakguard apply" in a terminal) are lost, so the total
// can only be low, never high. A block is one packet, so the total is an
// approximate count of blocked connection attempts.
package stats

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// DefaultPath is where the daemon keeps the stats: root-owned, readable by
// everyone, like the configuration next to it.
const DefaultPath = "/Library/Application Support/leakguard/stats.json"

// MaxGap is the longest time between two VPN samples that still counts as
// watched. A longer gap (the Mac slept, the daemon was stopped) adds no VPN
// time and no drop: nobody saw what happened meanwhile.
const MaxGap = 2 * time.Minute

const dayFormat = "2006-01-02"

// State is what the tracker saves. Field names are the file format.
type State struct {
	// Day is the local date the totals belong to, as 2006-01-02.
	Day string `json:"day"`
	// VPNKnown is set once the VPN has been sampled.
	VPNKnown  bool `json:"vpn_known"`
	Connected bool `json:"connected"`
	// Since is when the current session started (connected) or ended
	// (disconnected).
	Since      time.Time     `json:"since"`
	LastSample time.Time     `json:"last_sample"`
	VPN        time.Duration `json:"today_vpn_ns"`
	Drops      int           `json:"today_drops"`
	Blocks     uint64        `json:"today_blocks"`
	// Counter is the last block-counter reading, the baseline of the next
	// one, when CounterKnown is set.
	CounterKnown bool   `json:"counter_known"`
	Counter      uint64 `json:"counter"`
}

// Summary is what the apps show, at a given time.
type Summary struct {
	// Known is set once the VPN has been sampled; Fresh when the last sample
	// is recent (within MaxGap), so Connected and Since are current.
	Known, Fresh bool
	Connected    bool
	Since        time.Time
	// Day is the local date of the totals below.
	Day    string
	VPN    time.Duration
	Drops  int
	Blocks uint64
}

// Tracker turns samples into a State. It is not safe for concurrent use.
type Tracker struct {
	loc *time.Location
	s   State
}

// New returns an empty tracker whose days follow loc (nil means UTC).
func New(loc *time.Location) *Tracker {
	if loc == nil {
		loc = time.UTC
	}
	return &Tracker{loc: loc}
}

// Load reads the state at path. It always returns a usable tracker: a
// missing file starts fresh without an error; an unreadable or corrupt one
// starts fresh and returns the error, for the log.
func Load(path string, loc *time.Location) (*Tracker, error) {
	t := New(loc)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return t, err
	}
	var s State
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return t, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return t, fmt.Errorf("%s: unexpected data after the stats", path)
	}
	if _, err := time.Parse(dayFormat, s.Day); err != nil || s.VPN < 0 || s.Drops < 0 {
		return t, fmt.Errorf("%s: invalid stats", path)
	}
	t.s = s
	return t, nil
}

// Save writes s atomically, readable by everyone and writable only by its
// owner.
func Save(path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".stats-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// State returns a copy of the current state, for Save.
func (t *Tracker) State() State { return t.s }

// ObserveVPN records whether the VPN is connected at now.
func (t *Tracker) ObserveVPN(now time.Time, connected bool) {
	s := &t.s
	watched := t.watched(now)
	t.rollover(now)
	if watched && s.Connected {
		s.VPN += now.Sub(t.laterOfDayStart(s.LastSample, now))
	}
	switch {
	case !s.VPNKnown:
		s.Since = now
	case connected != s.Connected && watched:
		s.Since = now
		if s.Connected {
			s.Drops++
		}
	case connected != s.Connected && s.Connected:
		// Disconnected after a gap: the session ended when it was last seen.
		s.Since = s.LastSample
	case connected != s.Connected, !watched && connected:
		s.Since = now
	}
	s.VPNKnown, s.Connected, s.LastSample = true, connected, now
}

// ObserveBlocks records a reading of pf's block counter at now.
func (t *Tracker) ObserveBlocks(now time.Time, reading uint64) {
	s := &t.s
	t.rollover(now)
	if s.CounterKnown {
		if reading >= s.Counter {
			s.Blocks += reading - s.Counter
		} else {
			s.Blocks += reading
		}
	}
	s.Counter, s.CounterKnown = reading, true
}

// CounterReset records that the daemon reloaded or flushed the anchor, which
// sets pf's counter to zero.
func (t *Tracker) CounterReset() {
	t.s.Counter, t.s.CounterKnown = 0, true
}

// Summary returns the numbers to show at now. Totals of an earlier day read
// as zero; the time since a recent last sample counts as VPN time when the
// VPN was connected.
func (t *Tracker) Summary(now time.Time) Summary {
	s := t.s
	sum := Summary{Known: s.VPNKnown, Connected: s.Connected, Since: s.Since, Day: t.day(now)}
	sum.Fresh = s.VPNKnown && t.watched(now)
	if sum.Day == s.Day {
		sum.VPN, sum.Drops, sum.Blocks = s.VPN, s.Drops, s.Blocks
	}
	if sum.Fresh && s.Connected {
		sum.VPN += now.Sub(t.laterOfDayStart(s.LastSample, now))
	}
	return sum
}

// watched reports whether now follows the last VPN sample within MaxGap.
func (t *Tracker) watched(now time.Time) bool {
	gap := now.Sub(t.s.LastSample)
	return t.s.VPNKnown && gap >= 0 && gap <= MaxGap
}

// rollover starts a new day's totals when now is on another local date.
func (t *Tracker) rollover(now time.Time) {
	if d := t.day(now); d != t.s.Day {
		t.s.Day, t.s.VPN, t.s.Drops, t.s.Blocks = d, 0, 0, 0
	}
}

func (t *Tracker) day(now time.Time) string { return now.In(t.loc).Format(dayFormat) }

// laterOfDayStart returns from, or the start of now's day when from is
// earlier: only today's part of an interval counts.
func (t *Tracker) laterOfDayStart(from, now time.Time) time.Time {
	if sod := StartOfDay(now, t.loc); from.Before(sod) {
		return sod
	}
	return from
}

// StartOfDay returns the first instant of now's local date in loc. Where the
// clocks jump forward at midnight, the day starts at 01:00.
func StartOfDay(now time.Time, loc *time.Location) time.Time {
	local := now.In(loc)
	day := local.Format(dayFormat)
	y, m, d := local.Date()
	start := time.Date(y, m, d, 0, 0, 0, 0, loc)
	for start.In(loc).Format(dayFormat) != day {
		start = start.Add(time.Hour)
	}
	// time.Date may pick the later of two offsets; step back while the
	// earlier instant is still on the same date.
	for start.Add(-time.Hour).In(loc).Format(dayFormat) == day {
		start = start.Add(-time.Hour)
	}
	return start
}

// FormatDuration writes d in plain units that read the same in Spanish and
// English: "45 s", "12 min", "2 h 15 min", "3 d 4 h".
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int64(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int64(d/time.Minute))
	case d < 24*time.Hour:
		return pair(int64(d/time.Hour), "h", int64(d%time.Hour/time.Minute), "min")
	}
	return pair(int64(d/(24*time.Hour)), "d", int64(d%(24*time.Hour)/time.Hour), "h")
}

func pair(a int64, au string, b int64, bu string) string {
	if b == 0 {
		return fmt.Sprintf("%d %s", a, au)
	}
	return fmt.Sprintf("%d %s %d %s", a, au, b, bu)
}
