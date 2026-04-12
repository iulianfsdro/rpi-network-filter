package web

import "embed"

//go:embed all:static all:templates
var Content embed.FS
