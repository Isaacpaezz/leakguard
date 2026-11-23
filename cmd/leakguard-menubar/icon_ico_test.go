package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"testing"
)

// S1: the Windows tray loads icons with LoadImageW, which reads .ico files:
// the Linux colored icons (legible on light and dark taskbars) go into an
// .ico with one 32-bit image, bottom-up BGRA plus the AND mask, every
// pixel as in the PNG.
func TestICOFromLinuxIcons(t *testing.T) {
	for name, data := range map[string][]byte{
		"protected": linuxIconProtected,
		"outline":   linuxIconOutline,
		"notsetup":  linuxIconNotSetUp,
	} {
		src, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ico, err := icoFromPNG(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkICO(t, name, ico, src)
	}
	if _, err := icoFromPNG([]byte("not a png")); err == nil {
		t.Error("icoFromPNG of garbage: no error")
	}
	var big bytes.Buffer
	if err := png.Encode(&big, image.NewNRGBA(image.Rect(0, 0, 257, 1))); err != nil {
		t.Fatal(err)
	}
	if _, err := icoFromPNG(big.Bytes()); err == nil {
		t.Error("icoFromPNG of a 257-pixel-wide image: no error")
	}
}

func checkICO(t *testing.T, name string, ico []byte, src image.Image) {
	t.Helper()
	le := binary.LittleEndian
	w, h := src.Bounds().Dx(), src.Bounds().Dy()
	maskRow := (w + 31) / 32 * 4
	size := 40 + w*h*4 + maskRow*h
	if len(ico) != 22+size {
		t.Fatalf("%s: %d bytes, want %d", name, len(ico), 22+size)
	}
	// ICONDIR and its one ICONDIRENTRY.
	if le.Uint16(ico[0:]) != 0 || le.Uint16(ico[2:]) != 1 || le.Uint16(ico[4:]) != 1 {
		t.Errorf("%s: header % x", name, ico[:6])
	}
	if int(ico[6]) != w || int(ico[7]) != h || ico[8] != 0 || ico[9] != 0 ||
		le.Uint16(ico[10:]) != 1 || le.Uint16(ico[12:]) != 32 ||
		int(le.Uint32(ico[14:])) != size || le.Uint32(ico[18:]) != 22 {
		t.Errorf("%s: entry % x", name, ico[6:22])
	}
	// BITMAPINFOHEADER: the height counts the color and mask halves.
	bmp := ico[22:]
	if le.Uint32(bmp[0:]) != 40 || int(int32(le.Uint32(bmp[4:]))) != w || int(int32(le.Uint32(bmp[8:]))) != 2*h ||
		le.Uint16(bmp[12:]) != 1 || le.Uint16(bmp[14:]) != 32 || le.Uint32(bmp[16:]) != 0 {
		t.Errorf("%s: bitmap header % x", name, bmp[:40])
	}
	pixels, mask := bmp[40:40+w*h*4], bmp[40+w*h*4:]
	opaque := 0
	for y := 0; y < h; y++ {
		row := h - 1 - y // bottom-up
		for x := 0; x < w; x++ {
			c := image.NewNRGBA(image.Rect(0, 0, 1, 1))
			c.Set(0, 0, src.At(x, y))
			want := c.Pix // R, G, B, A, not premultiplied
			got := pixels[(row*w+x)*4:]
			if got[0] != want[2] || got[1] != want[1] || got[2] != want[0] || got[3] != want[3] {
				t.Fatalf("%s: pixel %d,%d = BGRA % x, want RGBA % x", name, x, y, got[:4], want)
			}
			transparent := mask[row*maskRow+x/8]&(0x80>>(x%8)) != 0
			if transparent != (want[3] == 0) {
				t.Fatalf("%s: mask at %d,%d = %v, alpha %d", name, x, y, transparent, want[3])
			}
			if want[3] != 0 {
				opaque++
			}
		}
	}
	if opaque == 0 {
		t.Errorf("%s is empty", name)
	}
}
