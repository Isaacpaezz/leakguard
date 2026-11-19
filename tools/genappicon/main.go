// Command genappicon draws the app icon of leakguard.app, a white shield on
// a blue rounded square, at every size macOS needs, into an .iconset folder
// that iconutil turns into AppIcon.icns. scripts/build-macos.sh runs it:
//
//	go run ./tools/genappicon build/AppIcon.iconset
//	iconutil -c icns -o AppIcon.icns build/AppIcon.iconset
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// samples per axis, for anti-aliasing.
const samples = 4

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) != 1 || !strings.HasSuffix(args[0], ".iconset") {
		fmt.Fprintln(stderr, "usage: go run ./tools/genappicon DIR.iconset")
		return 2
	}
	dir := args[0]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(stderr, "genappicon: %v\n", err)
		return 1
	}
	for _, pt := range []int{16, 32, 128, 256, 512} {
		for _, scale := range []int{1, 2} {
			name := fmt.Sprintf("icon_%dx%d.png", pt, pt)
			if scale == 2 {
				name = fmt.Sprintf("icon_%dx%d@2x.png", pt, pt)
			}
			if err := writePNG(filepath.Join(dir, name), draw(pt*scale)); err != nil {
				fmt.Fprintf(stderr, "genappicon: %v\n", err)
				return 1
			}
		}
	}
	return 0
}

func writePNG(path string, img image.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// draw renders the icon at size pixels. The shapes are defined on a
// 1024-unit canvas, like Apple's icon grid: an 824-unit rounded square with
// 100 units of margin, and the shield of the menu-bar icons, scaled up.
func draw(size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	k := 1024 / float64(size)
	top := color.NRGBA{R: 0x25, G: 0x63, B: 0xEB, A: 0xFF}
	bottom := color.NRGBA{R: 0x1E, G: 0x3A, B: 0x8A, A: 0xFF}
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var inSquare, inShield int
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/samples) * k
					y := (float64(py) + (float64(sy)+0.5)/samples) * k
					if roundedSquare(x, y) {
						inSquare++
						if shield(x, y) {
							inShield++
						}
					}
				}
			}
			if inSquare == 0 {
				continue
			}
			t := (float64(py) + 0.5) / float64(size)
			bg := mix(top, bottom, t)
			f := float64(inShield) / float64(inSquare)
			c := mix(bg, color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}, f)
			c.A = uint8(math.Round(255 * float64(inSquare) / (samples * samples)))
			img.SetNRGBA(px, py, c)
		}
	}
	return img
}

// roundedSquare reports whether (x, y), in 1024-unit coordinates, is inside
// the icon's rounded square.
func roundedSquare(x, y float64) bool {
	const lo, hi, r = 100.0, 924.0, 185.0
	if x < lo || x > hi || y < lo || y > hi {
		return false
	}
	cx := math.Max(lo+r, math.Min(hi-r, x))
	cy := math.Max(lo+r, math.Min(hi-r, y))
	return math.Hypot(x-cx, y-cy) <= r
}

// shield reports whether (x, y), in 1024-unit coordinates, is inside the
// shield: the shape of the menu-bar icons (cmd/leakguard-menubar/gen_icons.go,
// a 32-unit design) scaled to about 56% of the canvas height.
func shield(x, y float64) bool {
	const scale = 1024 * 0.56 / 27
	u := (x-512)/scale + 16
	v := (y-512)/scale + 16
	const cx, top, mid, bottom, half = 16.0, 2.5, 15.0, 29.5, 12.0
	if v < top || v > bottom {
		return false
	}
	if v <= mid {
		return math.Abs(u-cx) <= half
	}
	f := (v - mid) / (bottom - mid)
	return math.Abs(u-cx) <= half*math.Sqrt(1-f*f)
}

func mix(a, b color.NRGBA, t float64) color.NRGBA {
	l := func(p, q uint8) uint8 { return uint8(math.Round(float64(p) + (float64(q)-float64(p))*t)) }
	return color.NRGBA{R: l(a.R, b.R), G: l(a.G, b.G), B: l(a.B, b.B), A: l(a.A, b.A)}
}
