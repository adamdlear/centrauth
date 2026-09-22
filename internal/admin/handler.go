package admin

import (
	"log/slog"
	"net/http"

	"github.com/adamdlear/centrauth/internal/admin/templates"
	"github.com/adamdlear/centrauth/internal/middleware"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/service"
	"github.com/adamdlear/centrauth/internal/session"
)

type Handler struct {
	logger       *slog.Logger
	templates    *templates.Templates
	applications repository.ApplicationRepository
	clients      repository.ClientRepository
	operatorAuth *service.OperatorLoginService
	sessions     *session.OperatorManager
}

func NewHandler(logger *slog.Logger, tpl *templates.Templates, applications repository.ApplicationRepository, clients repository.ClientRepository, operatorAuth *service.OperatorLoginService, sessions *session.OperatorManager) *Handler {
	return &Handler{
		logger:       logger,
		templates:    tpl,
		applications: applications,
		clients:      clients,
		operatorAuth: operatorAuth,
		sessions:     sessions,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/login", h.operatorLoginPageHandler)
	mux.HandleFunc("POST /admin/auth/login", h.operatorLoginHandler)
	mux.HandleFunc("POST /admin/auth/logout", h.operatorLogoutHandler)
	mux.Handle("GET /admin", middleware.RequireOperator(http.HandlerFunc(h.dashboardHandler)))
	mux.Handle("POST /admin/apps", middleware.RequireOperator(http.HandlerFunc(h.createAppHandler)))
}
