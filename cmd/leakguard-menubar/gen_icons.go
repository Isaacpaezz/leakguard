//go:build ignore

// gen_icons draws the menu-bar icons as black template PNGs: macOS recolors
// them for light and dark menu bars. Run it with: go generate ./cmd/leakguard-menubar
package main

import (
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"
)

const (
	size    = 32 // pixels; shown at 16 points, so sharp on Retina displays
	samples = 4  // per axis, for anti-aliasing
)

// shield reports whether (x, y) is inside a shield inset by d pixels.
func shield(x, y, d float64) bool {
	const cx, top, mid, bottom, half = 16.0, 2.5, 15.0, 29.5, 12.0
	t, b, h := top+d, bottom-1.6*d, half-d
	if y < t || y > b {
		return false
	}
	if y <= mid {
		return math.Abs(x-cx) <= h
	}
	f := (y - mid) / (b - mid)
	return math.Abs(x-cx) <= h*math.Sqrt(1-f*f)
}

// slash is the distance from (x, y) to the diagonal stroke.
func slash(x, y float64) float64 {
	ax, ay, bx, by := 5.0, 3.0, 27.0, 29.0
	dx, dy := bx-ax, by-ay
	t := math.Max(0, math.Min(1, ((x-ax)*dx+(y-ay)*dy)/(dx*dx+dy*dy)))
	return math.Hypot(x-(ax+t*dx), y-(ay+t*dy))
}

var icons = map[string]func(x, y float64) bool{
	// Protected: a filled shield.
	"protected.png": func(x, y float64) bool { return shield(x, y, 0) },
	// Not protected or paused: a shield outline.
	"outline.png": func(x, y float64) bool { return shield(x, y, 0) && !shield(x, y, 2.5) },
	// Not set up: a shield outline crossed by a slash.
	"notsetup.png": func(x, y float64) bool {
		d := slash(x, y)
		if d <= 1.4 {
			return true
		}
		return d > 3 && shield(x, y, 0) && !shield(x, y, 2.5)
	},
}

func main() {
	for name, inside := range icons {
		img := image.NewNRGBA(image.Rect(0, 0, size, size))
		for py := 0; py < size; py++ {
			for px := 0; px < size; px++ {
				n := 0
				for sy := 0; sy < samples; sy++ {
					for sx := 0; sx < samples; sx++ {
						x := float64(px) + (float64(sx)+0.5)/samples
						y := float64(py) + (float64(sy)+0.5)/samples
						if inside(x, y) {
							n++
						}
					}
				}
				img.SetNRGBA(px, py, color.NRGBA{A: uint8(255 * n / (samples * samples))})
			}
		}
		f, err := os.Create(filepath.Join("icons", name))
		if err != nil {
			log.Fatal(err)
		}
		if err := png.Encode(f, img); err != nil {
			log.Fatal(err)
		}
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}
}
