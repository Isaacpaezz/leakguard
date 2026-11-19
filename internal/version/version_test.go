package version

import "testing"

// S1: a build without -ldflags reports "dev".
func TestDefaultIsDev(t *testing.T) {
	if Version != "dev" {
		t.Errorf("Version = %q, want %q", Version, "dev")
	}
	if got := String(); got != "dev" {
		t.Errorf("String() = %q, want %q", got, "dev")
	}
}

// S1: the release build injects the tag version; an empty injection still
// reads "dev".
func TestString(t *testing.T) {
	defer func(v string) { Version = v }(Version)
	for in, want := range map[string]string{"0.1.0": "0.1.0", "1.2.3-ci": "1.2.3-ci", "": "dev", "  ": "dev"} {
		Version = in
		if got := String(); got != want {
			t.Errorf("Version %q: String() = %q, want %q", in, got, want)
		}
	}
}
