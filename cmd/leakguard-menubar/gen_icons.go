//go:build ignore

// gen_icons draws the menu-bar icons as black template PNGs: macOS recolors
// them for light and dark menu bars. It also draws the Linux tray icons,
// which no panel recolors: the same shapes in a dark color inside a white
// halo, so they show on light and dark panels.
// Run it with: go generate ./cmd/leakguard-menubar
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

// linuxIcons are the Linux tray icons: a shape of icons and its color.
var linuxIcons = map[string]struct {
	shape string
	core  color.NRGBA
}{
	"linux-protected.png": {"protected.png", color.NRGBA{R: 0x1b, G: 0x7a, B: 0x35, A: 0xff}},
	"linux-outline.png":   {"outline.png", color.NRGBA{R: 0x33, G: 0x33, B: 0x33, A: 0xff}},
	"linux-notsetup.png":  {"notsetup.png", color.NRGBA{R: 0x33, G: 0x33, B: 0x33, A: 0xff}},
}

// halo is the white rim around a shape, haloWidth pixels wide.
const haloWidth = 1.5

// nearShape reports whether (x, y) is within haloWidth of the shape.
func nearShape(inside func(x, y float64) bool, x, y float64) bool {
	for _, r := range []float64{haloWidth / 2, haloWidth} {
		for i := 0; i < 16; i++ {
			a := float64(i) * math.Pi / 8
			if inside(x+r*math.Cos(a), y+r*math.Sin(a)) {
				return true
			}
		}
	}
	return false
}

// drawLinux samples the shape in core color, its halo in white, and
// averages the samples.
func drawLinux(inside func(x, y float64) bool, core color.NRGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a int
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					x := float64(px) + (float64(sx)+0.5)/samples
					y := float64(py) + (float64(sy)+0.5)/samples
					switch {
					case inside(x, y):
						r, g, b, a = r+int(core.R), g+int(core.G), b+int(core.B), a+1
					case nearShape(inside, x, y):
						r, g, b, a = r+255, g+255, b+255, a+1
					}
				}
			}
			if a > 0 {
				img.SetNRGBA(px, py, color.NRGBA{
					R: uint8(r / a), G: uint8(g / a), B: uint8(b / a),
					A: uint8(255 * a / (samples * samples)),
				})
			}
		}
	}
	return img
}

func writePNG(name string, img image.Image) {
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

func main() {
	for name, icon := range linuxIcons {
		writePNG(name, drawLinux(icons[icon.shape], icon.core))
	}
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
