package main

import (
	"bytes"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

// S1: one icon set with every size iconutil needs, from 16 px to 1024 px.
func TestRunWritesIconSet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "AppIcon.iconset")
	var errb bytes.Buffer
	if code := run([]string{dir}, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	want := map[string]int{
		"icon_16x16.png": 16, "icon_16x16@2x.png": 32,
		"icon_32x32.png": 32, "icon_32x32@2x.png": 64,
		"icon_128x128.png": 128, "icon_128x128@2x.png": 256,
		"icon_256x256.png": 256, "icon_256x256@2x.png": 512,
		"icon_512x512.png": 512, "icon_512x512@2x.png": 1024,
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(want) {
		t.Fatalf("%d files, %v; want %d", len(entries), err, len(want))
	}
	for name, size := range want {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		img, err := png.Decode(f)
		f.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b := img.Bounds(); b.Dx() != size || b.Dy() != size {
			t.Errorf("%s is %dx%d, want %d", name, b.Dx(), b.Dy(), size)
		}
	}
}

// The 1024 px icon: a white shield on a blue rounded square, transparent
// corners.
func TestDraw(t *testing.T) {
	img := draw(1024)
	alpha := func(x, y int) uint8 { return img.NRGBAAt(x, y).A }
	if a := alpha(0, 0); a != 0 {
		t.Errorf("corner alpha = %d, want transparent", a)
	}
	c := img.NRGBAAt(512, 512)
	if c.A != 255 || c.R < 240 || c.G < 240 || c.B < 240 {
		t.Errorf("center = %+v, want opaque white (the shield)", c)
	}
	bg := img.NRGBAAt(512, 130)
	if bg.A != 255 || bg.B <= bg.R {
		t.Errorf("top of the square = %+v, want opaque blue", bg)
	}
}

func TestRunRejects(t *testing.T) {
	var errb bytes.Buffer
	if code := run(nil, &errb); code != 2 || errb.String() != "usage: go run ./tools/genappicon DIR.iconset\n" {
		t.Errorf("exit %d, stderr %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"out/AppIcon"}, &errb); code != 2 {
		t.Errorf("a folder without .iconset: exit %d, want 2", code)
	}
}
