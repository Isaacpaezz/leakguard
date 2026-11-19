package menubar

import "testing"

// S3: the sealed system volume is read-only (like a mounted DMG); a temp
// folder on the data volume is writable.
func TestReadOnlyVolume(t *testing.T) {
	if ro, err := ReadOnlyVolume("/System"); err != nil || !ro {
		t.Errorf("ReadOnlyVolume(/System) = %v, %v; want true, nil", ro, err)
	}
	if ro, err := ReadOnlyVolume(t.TempDir()); err != nil || ro {
		t.Errorf("ReadOnlyVolume(temp) = %v, %v; want false, nil", ro, err)
	}
	if _, err := ReadOnlyVolume("/no/such/volume/leakguard.app"); err == nil {
		t.Error("ReadOnlyVolume(missing) = nil error")
	}
}
