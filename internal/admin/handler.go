package admin

import (
	"log/slog"
	"net/http"

	"github.com/adamdlear/centrauth/internal/admin/templates"
	"github.com/adamdlear/centrauth/internal/middleware"
	"github.com/adamdlear/centrauth/internal/repository"
)

type Handler struct {
	logger       *slog.Logger
	templates    *templates.Templates
	applications repository.ApplicationRepository
	clients      repository.ClientRepository
}

func NewHandler(logger *slog.Logger, tpl *templates.Templates, applications repository.ApplicationRepository, clients repository.ClientRepository) *Handler {
	return &Handler{
		logger:       logger,
		templates:    tpl,
		applications: applications,
		clients:      clients,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("GET /admin", middleware.RequireAuth(http.HandlerFunc(h.dashboardHandler)))
	mux.Handle("POST /admin/apps", middleware.RequireAuth(http.HandlerFunc(h.createAppHandler)))
}
