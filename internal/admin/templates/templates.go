package templates

import (
	"embed"
	"html/template"
)

//go:embed *.html
var templateFiles embed.FS

type Templates struct {
	pages map[string]*template.Template
}

var pages = []string{
	"dashboard.html",
	"setup.html",
	"operator_login.html",
	"clients.html",
	"app_list.html",
	"app_new.html",
	"app_registered.html",
	"app_edit.html",
	"client_new.html",
	"client_registered.html",
	"client_detail.html",
	"authorize_prompt.html",
	"authorize_error.html",
}

func New() *Templates {
	parsed := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		parsed[page] = template.Must(template.New(page).ParseFS(templateFiles, "base.html", page))
	}
	return &Templates{pages: parsed}
}

// Get returns the parsed template set for a page file (for example
// "dashboard.html").
func (t *Templates) Get(page string) *template.Template {
	return t.pages[page]
}
