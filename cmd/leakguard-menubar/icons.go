package main

import _ "embed"

//go:generate go run gen_icons.go

// Template icons: black shapes on transparency, which macOS recolors for
// light and dark menu bars.
var (
	//go:embed icons/protected.png
	iconProtected []byte
	//go:embed icons/outline.png
	iconOutline []byte
	//go:embed icons/notsetup.png
	iconNotSetUp []byte
)

// Linux tray icons: the same shapes in color inside a white halo, because
// Linux panels do not recolor icons and may be light or dark.
var (
	//go:embed icons/linux-protected.png
	linuxIconProtected []byte
	//go:embed icons/linux-outline.png
	linuxIconOutline []byte
	//go:embed icons/linux-notsetup.png
	linuxIconNotSetUp []byte
)
