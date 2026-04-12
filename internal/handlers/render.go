package handlers

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
)

type Renderer struct {
	tmplFS fs.FS
	cache  map[string]*template.Template
}

func NewRenderer(tmplFS fs.FS) *Renderer {
	return &Renderer{
		tmplFS: tmplFS,
		cache:  make(map[string]*template.Template),
	}
}

func (r *Renderer) RenderPage(w http.ResponseWriter, name string, data any) {
	tmpl, ok := r.cache[name]
	if !ok {
		var err error
		tmpl, err = template.ParseFS(r.tmplFS,
			filepath.Join("templates", "layout.html"),
			filepath.Join("templates", name),
		)
		if err != nil {
			log.Printf("[ERROR] Failed to parse template %s: %v", name, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		r.cache[name] = tmpl
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("[ERROR] Failed to render template %s: %v", name, err)
	}
}

func (r *Renderer) RenderLogin(w http.ResponseWriter, data any) {
	tmpl, err := template.ParseFS(r.tmplFS, filepath.Join("templates", "login.html"))
	if err != nil {
		log.Printf("[ERROR] Failed to parse login template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

func JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func JSONError(w http.ResponseWriter, status int, msg string) {
	JSON(w, status, map[string]string{"error": msg})
}
