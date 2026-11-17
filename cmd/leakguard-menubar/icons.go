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
