package main

import (
	"embed"
	"io/fs"
)

//go:embed all:web/dist
var distFS embed.FS

func webRoot() fs.FS {
	sub, err := fs.Sub(distFS, "web/dist")
	if err != nil {
		panic(err)
	}
	return sub
}
