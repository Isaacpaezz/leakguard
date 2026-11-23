package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/draw"
	"image/png"
)

// icoFromPNG converts a PNG icon into the .ico file that the Windows tray
// loads with LoadImageW: one 32-bit image with straight alpha, stored as a
// bottom-up BGRA bitmap followed by the AND mask (set where a pixel is
// fully transparent), which every Windows version reads.
func icoFromPNG(data []byte) ([]byte, error) {
	src, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 1 || h < 1 || w > 256 || h > 256 {
		return nil, errors.New("an icon is 1 to 256 pixels wide and high")
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Bounds(), src, b.Min, draw.Src)

	maskRow := (w + 31) / 32 * 4
	size := 40 + w*h*4 + maskRow*h
	le := binary.LittleEndian
	out := make([]byte, 0, 22+size)
	// ICONDIR: reserved, type 1 (icon), one image.
	out = le.AppendUint16(out, 0)
	out = le.AppendUint16(out, 1)
	out = le.AppendUint16(out, 1)
	// ICONDIRENTRY: 256 is written as 0.
	out = append(out, byte(w), byte(h), 0, 0)
	out = le.AppendUint16(out, 1)  // planes
	out = le.AppendUint16(out, 32) // bits per pixel
	out = le.AppendUint32(out, uint32(size))
	out = le.AppendUint32(out, 22)
	// BITMAPINFOHEADER: the height counts the color and the mask halves.
	out = le.AppendUint32(out, 40)
	out = le.AppendUint32(out, uint32(w))
	out = le.AppendUint32(out, uint32(2*h))
	out = le.AppendUint16(out, 1)
	out = le.AppendUint16(out, 32)
	out = append(out, make([]byte, 24)...) // BI_RGB, then sizes and colors left 0
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			p := img.Pix[img.PixOffset(x, y):]
			out = append(out, p[2], p[1], p[0], p[3])
		}
	}
	for y := h - 1; y >= 0; y-- {
		row := make([]byte, maskRow)
		for x := 0; x < w; x++ {
			if img.Pix[img.PixOffset(x, y)+3] == 0 {
				row[x/8] |= 0x80 >> (x % 8)
			}
		}
		out = append(out, row...)
	}
	return out, nil
}
