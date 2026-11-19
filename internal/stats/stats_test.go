package stats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
	_ "time/tzdata" // the DST tests must not depend on the host's zone files
)

func zone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

var caracas = func() *time.Location {
	loc, err := time.LoadLocation("America/Caracas")
	if err != nil {
		panic(err)
	}
	return loc
}()

func at(loc *time.Location, s string) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04:05", s, loc)
	if err != nil {
		panic(err)
	}
	return t
}

// sampleEvery feeds connected every step from start until end (included).
func sampleEvery(tr *Tracker, start, end time.Time, step time.Duration, connected bool) {
	for now := start; !now.After(end); now = now.Add(step) {
		tr.ObserveVPN(now, connected)
	}
}

// S1: a session starts when the VPN connects and ends when it disconnects;
// S2/S3: connected time and drops add up for today.
func TestSessionAndDrops(t *testing.T) {
	tr := New(caracas)
	t0 := at(caracas, "2026-11-16 10:00:00")
	tr.ObserveVPN(t0, true)
	sampleEvery(tr, t0.Add(5*time.Second), t0.Add(time.Hour), 5*time.Second, true)
	s := tr.Summary(t0.Add(time.Hour))
	if !s.Known || !s.Fresh || !s.Connected || !s.Since.Equal(t0) || s.VPN != time.Hour || s.Drops != 0 || s.Day != "2026-11-16" {
		t.Fatalf("after 1 h connected: %+v", s)
	}
	down := t0.Add(time.Hour + 5*time.Second)
	tr.ObserveVPN(down, false)
	tr.ObserveVPN(down.Add(5*time.Second), false)
	s = tr.Summary(down.Add(5 * time.Second))
	if s.Connected || !s.Since.Equal(down) || s.Drops != 1 || s.VPN != time.Hour+5*time.Second {
		t.Fatalf("after the drop: %+v", s)
	}
	up := down.Add(10 * time.Second)
	tr.ObserveVPN(up, true)
	tr.ObserveVPN(up.Add(5*time.Second), false)
	if s = tr.Summary(up.Add(5 * time.Second)); s.Drops != 2 || !s.Since.Equal(up.Add(5*time.Second)) {
		t.Fatalf("after the second drop: %+v", s)
	}
}

// A disconnected VPN at the first sample is not a drop.
func TestFirstSampleIsNotADrop(t *testing.T) {
	tr := New(caracas)
	t0 := at(caracas, "2026-11-16 10:00:00")
	tr.ObserveVPN(t0, false)
	s := tr.Summary(t0)
	if !s.Known || s.Connected || s.Drops != 0 || !s.Since.Equal(t0) || s.VPN != 0 {
		t.Fatalf("Summary() = %+v", s)
	}
	if s := New(caracas).Summary(t0); s.Known || s.Fresh || s.Day != "2026-11-16" {
		t.Fatalf("empty tracker Summary() = %+v", s)
	}
}

// A gap longer than MaxGap (the Mac slept, or the daemon was stopped) adds
// no VPN time and no drop: nobody saw what happened meanwhile.
func TestLongGapAddsNothing(t *testing.T) {
	tr := New(caracas)
	t0 := at(caracas, "2026-11-16 10:00:00")
	tr.ObserveVPN(t0, true)
	later := t0.Add(3 * time.Hour)
	tr.ObserveVPN(later, true)
	if s := tr.Summary(later); s.VPN != 0 || !s.Since.Equal(later) || s.Drops != 0 {
		t.Fatalf("connected again after a long gap: %+v; want a new session and no time", s)
	}
	end := later.Add(5 * time.Second)
	tr.ObserveVPN(end, true)
	tr.ObserveVPN(end.Add(3*time.Hour), false)
	if s := tr.Summary(end.Add(3 * time.Hour)); s.Drops != 0 || !s.Since.Equal(end) || s.VPN != 5*time.Second {
		t.Fatalf("disconnected after a long gap: %+v; want no drop, ended when last seen", s)
	}
	if s := tr.Summary(end.Add(3 * time.Hour)); s.Fresh != true {
		t.Fatalf("a just-sampled tracker is not fresh: %+v", s)
	}
	if s := tr.Summary(end.Add(6 * time.Hour)); s.Fresh {
		t.Fatalf("a tracker without samples for 3 h is fresh: %+v", s)
	}
	// A clock that goes back adds nothing either.
	back := New(caracas)
	back.ObserveVPN(t0, true)
	back.ObserveVPN(t0.Add(-time.Minute), true)
	if s := back.Summary(t0.Add(-time.Minute)); s.VPN != 0 {
		t.Fatalf("a clock going back added %v", s.VPN)
	}
}

// The ongoing interval since the last sample counts, when it is short.
func TestSummaryAddsTheOngoingInterval(t *testing.T) {
	tr := New(caracas)
	t0 := at(caracas, "2026-11-16 10:00:00")
	tr.ObserveVPN(t0, true)
	if s := tr.Summary(t0.Add(30 * time.Second)); s.VPN != 30*time.Second {
		t.Fatalf("VPN = %v, want 30s", s.VPN)
	}
	if s := tr.Summary(t0.Add(time.Hour)); s.VPN != 0 {
		t.Fatalf("VPN after a long gap = %v, want 0", s.VPN)
	}
}

// S2: blocks are the sum of counter deltas; a lower reading means pf reset
// the counter, so the reading itself is the delta.
func TestBlocks(t *testing.T) {
	tr := New(caracas)
	t0 := at(caracas, "2026-11-16 10:00:00")
	steps := []struct {
		reading uint64
		want    uint64
	}{
		{100, 0}, // first reading ever: a baseline, its history is unknown
		{114, 14},
		{114, 14},
		{3, 17}, // reset by pf: 3 new blocks
		{10, 24},
	}
	for i, s := range steps {
		tr.ObserveBlocks(t0.Add(time.Duration(i)*time.Second), s.reading)
		if got := tr.Summary(t0.Add(time.Duration(i) * time.Second)).Blocks; got != s.want {
			t.Fatalf("after reading %d: blocks = %d, want %d", s.reading, got, s.want)
		}
	}
	// The daemon reloaded the anchor: the next reading counts from zero.
	tr.CounterReset()
	tr.ObserveBlocks(t0.Add(time.Minute), 5)
	if got := tr.Summary(t0.Add(time.Minute)).Blocks; got != 29 {
		t.Fatalf("after a reset and 5 blocks: %d, want 29", got)
	}
	fresh := New(caracas)
	fresh.CounterReset()
	fresh.ObserveBlocks(t0, 7)
	if got := fresh.Summary(t0).Blocks; got != 7 {
		t.Fatalf("a reading after a reload by this daemon = %d, want 7", got)
	}
}

// S5: totals survive a daemon restart; the first reading after it counts
// only its delta from the saved baseline, and a counter reset meanwhile
// never counts more than the reading. Nothing is counted twice.
func TestRestartNeverDoubleCounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "stats.json")
	t0 := at(caracas, "2026-11-16 10:00:00")
	tr := New(caracas)
	tr.ObserveVPN(t0, true)
	tr.CounterReset()
	tr.ObserveBlocks(t0, 40)
	if err := Save(path, tr.State()); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("stats file mode = %v, %v; want 0644", fi, err)
	}
	for _, tc := range []struct {
		name    string
		reading uint64
		want    uint64
	}{
		{"same counter", 55, 55},
		{"same counter, no new blocks", 40, 40},
		{"reset meanwhile, lower", 6, 46},
		{"reset meanwhile, higher: at most the reading", 45, 45},
	} {
		got, err := Load(path, caracas)
		if err != nil {
			t.Fatal(err)
		}
		got.ObserveBlocks(t0.Add(time.Minute), tc.reading)
		if b := got.Summary(t0.Add(time.Minute)).Blocks; b != tc.want {
			t.Errorf("%s: blocks = %d, want %d", tc.name, b, tc.want)
		}
	}
	got, _ := Load(path, caracas)
	if s := got.Summary(t0.Add(30 * time.Second)); !s.Known || !s.Connected || !s.Since.Equal(t0) {
		t.Fatalf("loaded session = %+v", s)
	}
	// A restart within MaxGap continues the session and its time.
	got.ObserveVPN(t0.Add(30*time.Second), true)
	if s := got.Summary(t0.Add(30 * time.Second)); !s.Since.Equal(t0) || s.VPN != 30*time.Second {
		t.Fatalf("session after a quick restart = %+v", s)
	}
}

// A missing or corrupt file starts fresh and never fails the daemon.
func TestLoadMissingOrCorrupt(t *testing.T) {
	dir := t.TempDir()
	tr, err := Load(filepath.Join(dir, "none.json"), caracas)
	if err != nil || tr == nil || tr.Summary(time.Now()).Known {
		t.Fatalf("Load(missing) = %v, %v; want a fresh tracker", tr, err)
	}
	for _, data := range []string{"{not json", `{"day":"x"}`, `{"day":"2026-11-16"} {}`, `{"unknown":1}`} {
		p := filepath.Join(dir, "bad.json")
		os.WriteFile(p, []byte(data), 0o644)
		tr, err := Load(p, caracas)
		if err == nil || tr == nil {
			t.Fatalf("Load(%q) = %v, %v; want a fresh tracker and an error", data, tr, err)
		}
		if s := tr.Summary(time.Now()); s.Known || s.Blocks != 0 {
			t.Fatalf("Load(%q) kept data: %+v", data, s)
		}
	}
	// A directory where the file should be: Load starts fresh, Save fails.
	p := filepath.Join(dir, "isdir")
	os.Mkdir(p, 0o755)
	if tr, err := Load(p, caracas); tr == nil || err == nil {
		t.Fatalf("Load(dir) = %v, %v", tr, err)
	}
	if err := Save(p, New(caracas).State()); err == nil {
		t.Fatal("Save over a directory succeeded")
	}
}

func TestSavedFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	t0 := at(time.UTC, "2026-11-16 10:00:00")
	tr := New(time.UTC)
	tr.ObserveVPN(t0, true)
	if err := Save(path, tr.State()); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"day", "vpn_known", "connected", "since", "last_sample", "today_vpn_ns", "today_drops", "today_blocks", "counter_known", "counter"} {
		if _, ok := m[k]; !ok {
			t.Errorf("saved stats lack %q: %s", k, data)
		}
	}
}

// S3: "today" resets at local midnight, also in Caracas (no DST).
func TestDailyResetAtLocalMidnight(t *testing.T) {
	tr := New(caracas)
	start := at(caracas, "2026-11-16 23:59:00")
	tr.ObserveVPN(start, true)
	tr.CounterReset()
	tr.ObserveBlocks(start, 9)
	sampleEvery(tr, start.Add(5*time.Second), at(caracas, "2026-11-16 23:59:55"), 5*time.Second, true)
	if s := tr.Summary(at(caracas, "2026-11-16 23:59:55")); s.Blocks != 9 || s.VPN != 55*time.Second || s.Day != "2026-11-16" {
		t.Fatalf("before midnight: %+v", s)
	}
	// Midnight passed but no sample yet: the old day no longer counts.
	if s := tr.Summary(at(caracas, "2026-11-17 00:00:01")); s.Blocks != 0 || s.Drops != 0 || s.Day != "2026-11-17" || s.VPN != time.Second {
		t.Fatalf("summary after midnight: %+v", s)
	}
	after := at(caracas, "2026-11-17 00:00:05")
	tr.ObserveVPN(after, false)
	tr.ObserveBlocks(after, 12)
	s := tr.Summary(after)
	if s.Day != "2026-11-17" || s.VPN != 5*time.Second || s.Drops != 1 || s.Blocks != 3 || !s.Since.Equal(after) {
		t.Fatalf("after midnight: %+v; want only today's 5 s, 1 drop, 3 blocks", s)
	}
	// Midnight in Caracas is 04:00 UTC: the UTC date does not decide.
	utcLate := time.Date(2026, 11, 18, 3, 59, 0, 0, time.UTC)
	tr.ObserveVPN(utcLate, false)
	if got := tr.Summary(utcLate).Day; got != "2026-11-17" {
		t.Fatalf("day at 23:59 Caracas = %q", got)
	}
}

// S3: across DST changes a day lasts 23 or 25 hours, and in Santiago the
// clocks jump at midnight, so midnight itself does not exist.
func TestDailyResetAcrossDST(t *testing.T) {
	for _, tc := range []struct {
		zone, day, next string
		length          time.Duration
	}{
		{"America/New_York", "2026-03-08", "2026-03-09", 23 * time.Hour},
		{"America/New_York", "2026-11-01", "2026-11-02", 25 * time.Hour},
		{"America/Santiago", "2026-09-06", "2026-09-07", 23 * time.Hour},
		{"America/Santiago", "2026-04-04", "2026-04-05", 25 * time.Hour},
		{"America/Caracas", "2026-11-16", "2026-11-17", 24 * time.Hour},
	} {
		t.Run(tc.zone+" "+tc.day, func(t *testing.T) {
			loc := zone(t, tc.zone)
			start := StartOfDay(at(loc, tc.day+" 12:00:00"), loc)
			end := StartOfDay(at(loc, tc.next+" 12:00:00"), loc)
			if got := end.Sub(start); got != tc.length {
				t.Fatalf("%s lasts %v, want %v", tc.day, got, tc.length)
			}
			tr := New(loc)
			// Connected since 30 min before the day, sampled every minute.
			sampleEvery(tr, start.Add(-30*time.Minute), end.Add(-time.Minute), time.Minute, true)
			s := tr.Summary(end.Add(-time.Minute))
			if s.Day != tc.day || s.VPN != tc.length-time.Minute {
				t.Fatalf("at the end of the day: %+v; want %v on %s", s, tc.length-time.Minute, tc.day)
			}
			tr.ObserveVPN(end.Add(time.Minute), true)
			if s := tr.Summary(end.Add(time.Minute)); s.Day != tc.next || s.VPN != time.Minute {
				t.Fatalf("after midnight: %+v; want 1 min on %s", s, tc.next)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{-time.Minute, "0 s"},
		{0, "0 s"},
		{45 * time.Second, "45 s"},
		{59*time.Second + 999*time.Millisecond, "59 s"},
		{time.Minute, "1 min"},
		{12*time.Minute + 30*time.Second, "12 min"},
		{time.Hour, "1 h"},
		{2*time.Hour + 15*time.Minute, "2 h 15 min"},
		{24 * time.Hour, "1 d"},
		{3*24*time.Hour + 4*time.Hour + 59*time.Minute, "3 d 4 h"},
	} {
		if got := FormatDuration(tc.d); got != tc.want {
			t.Errorf("FormatDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
