package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed ui/*
var uiFiles embed.FS

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if !s.Config().WebUI {
		http.NotFound(w, r)
		return
	}
	sub, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	if _, err := fs.Stat(sub, path); err != nil {
		if strings.Contains(path, ".") {
			http.NotFound(w, r)
			return
		}
		path = "index.html"
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFileFS(w, r, sub, path)
}
