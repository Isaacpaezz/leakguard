package main

import (
	"bytes"
	"image/png"
	"testing"
)

func TestIconsAreTemplatePNGs(t *testing.T) {
	for name, data := range map[string][]byte{
		"protected": iconProtected,
		"outline":   iconOutline,
		"notsetup":  iconNotSetUp,
	} {
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b := img.Bounds()
		if b.Dx() != 32 || b.Dy() != 32 {
			t.Errorf("%s is %dx%d, want 32x32", name, b.Dx(), b.Dy())
		}
		opaque := 0
		for y := b.Min.Y; y < b.Max.Y; y++ {
			for x := b.Min.X; x < b.Max.X; x++ {
				r, g, bl, a := img.At(x, y).RGBA()
				if r|g|bl != 0 {
					t.Fatalf("%s has a colored pixel at %d,%d; template icons are black", name, x, y)
				}
				if a == 0xffff {
					opaque++
				}
			}
		}
		if opaque == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}
