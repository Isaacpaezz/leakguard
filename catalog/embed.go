// Package catalog embeds the service catalog files so released binaries carry
// the ranges they were built with. Load them with internal/catalog.Embedded.
package catalog

import "embed"

// Files holds services/*.json.
//
//go:embed services/*.json
var Files embed.FS
