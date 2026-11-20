// Package web embeds the panel's static frontend (pages, css, js).
// P0 ships a dark-mode skeleton; the full Alpine.js + HTMX dashboard lands in P8.
package web

import "embed"

//go:embed all:static all:pages
var FS embed.FS
