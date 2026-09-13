package internal

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:embed templates/*
var templateFiles embed.FS

type templates struct {
	login     *template.Template
	dashboard *template.Template
}

func newTemplates() *templates {
	tmplFS, err := fs.Sub(templateFiles, "templates")
	if err != nil {
		panic(err)
	}

	login := template.Must(template.New("login.html").ParseFS(tmplFS, "base.html", "login.html"))
	dashboard := template.Must(template.New("dashboard.html").ParseFS(tmplFS, "base.html", "dashboard.html"))

	return &templates{login: login, dashboard: dashboard}
}
