package templates

import (
	"embed"
	"html/template"
)

//go:embed *.html
var templateFiles embed.FS

type Templates struct {
	Login         *template.Template
	Dashboard     *template.Template
	Setup         *template.Template
	OperatorLogin *template.Template
}

func New() *Templates {
	login := template.Must(template.New("login.html").ParseFS(templateFiles, "base.html", "login.html"))
	dashboard := template.Must(template.New("dashboard.html").ParseFS(templateFiles, "base.html", "dashboard.html"))
	setup := template.Must(template.New("setup.html").ParseFS(templateFiles, "base.html", "setup.html"))
	operatorLogin := template.Must(template.New("operator_login.html").ParseFS(templateFiles, "base.html", "operator_login.html"))

	return &Templates{Login: login, Dashboard: dashboard, Setup: setup, OperatorLogin: operatorLogin}
}
