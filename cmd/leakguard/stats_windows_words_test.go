package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Isaacpaezz/leakguard/internal/ipc"
)

// On Windows leakguard status leaves the blocks out of "Today:", because
// Windows cannot count them yet.
func TestStatusTodayLeavesOutBlocksOnWindows(t *testing.T) {
	withWindowsWords(t)
	var b strings.Builder
	printStats(&b, &ipc.Stats{TodayBlocks: 7, TodayDrops: 2, TodayVPNSeconds: 3600}, time.Now())
	if got, want := b.String(), "Today:\tVPN dropped 2 times · 1 h on the VPN\n"; got != want {
		t.Errorf("printStats() = %q, want %q", got, want)
	}
	b.Reset()
	printStats(&b, &ipc.Stats{}, time.Now())
	if got, want := b.String(), "Today:\tVPN never dropped · 0 s on the VPN\n"; got != want {
		t.Errorf("printStats() = %q, want %q", got, want)
	}
}

// Elsewhere the blocks stay.
func TestStatusTodayKeepsBlocksElsewhere(t *testing.T) {
	old := windowsWords
	windowsWords = false
	t.Cleanup(func() { windowsWords = old })
	var b strings.Builder
	printStats(&b, &ipc.Stats{TodayBlocks: 7, TodayDrops: 2, TodayVPNSeconds: 3600}, time.Now())
	if got, want := b.String(), "Today:\t7 blocks · VPN dropped 2 times · 1 h on the VPN\n"; got != want {
		t.Errorf("printStats() = %q, want %q", got, want)
	}
}
