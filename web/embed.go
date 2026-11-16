package web

import "embed"

// FS embeds all HTML templates and static CSS/JS assets into the single binary.
//
//go:embed templates/*.html static/css/*.css static/js/*.js
var FS embed.FS
