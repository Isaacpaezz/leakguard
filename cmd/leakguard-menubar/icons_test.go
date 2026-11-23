package main

import (
	"bytes"
	"image/color"
	"image/png"
	"math"
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

// S1: Linux panels may be light or dark and do not recolor template icons,
// so each Linux icon must stand out on both a white and a black panel.
func TestLinuxIconsShowOnLightAndDarkPanels(t *testing.T) {
	icons := map[string][]byte{
		"protected": linuxIconProtected,
		"outline":   linuxIconOutline,
		"notsetup":  linuxIconNotSetUp,
	}
	seen := map[string]string{}
	for name, data := range icons {
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b := img.Bounds()
		if b.Dx() != 32 || b.Dy() != 32 {
			t.Errorf("%s is %dx%d, want 32x32", name, b.Dx(), b.Dy())
		}
		for _, panel := range []float64{0, 1} {
			visible := 0
			for y := b.Min.Y; y < b.Max.Y; y++ {
				for x := b.Min.X; x < b.Max.X; x++ {
					if math.Abs(luminanceOver(img.At(x, y), panel)-panel) >= 0.5 {
						visible++
					}
				}
			}
			if visible < 60 {
				t.Errorf("%s: only %d pixels stand out on a panel of luminance %v, want at least 60", name, visible, panel)
			}
		}
		if other, ok := seen[string(data)]; ok {
			t.Errorf("%s and %s are the same icon", name, other)
		}
		seen[string(data)] = name
	}
}

// luminanceOver is the luminance (0 to 1) of c drawn over a gray panel.
func luminanceOver(c color.Color, panel float64) float64 {
	r, g, b, a := c.RGBA()
	alpha := float64(a) / 0xffff
	// RGBA returns premultiplied values.
	lum := (0.2126*float64(r) + 0.7152*float64(g) + 0.0722*float64(b)) / 0xffff
	return lum + panel*(1-alpha)
}
