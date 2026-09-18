package templates

import (
	"embed"
	"html/template"
)

//go:embed *.html
var templateFiles embed.FS

type Templates struct {
	Login     *template.Template
	Dashboard *template.Template
}

func New() *Templates {
	login := template.Must(template.New("login.html").ParseFS(templateFiles, "base.html", "login.html"))
	dashboard := template.Must(template.New("dashboard.html").ParseFS(templateFiles, "base.html", "dashboard.html"))

	return &Templates{Login: login, Dashboard: dashboard}
}
