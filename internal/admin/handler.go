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
	apps         *service.AppService
	providers    *service.ProviderService
	operatorAuth *service.OperatorLoginService
	sessions     *session.OperatorManager
}

func NewHandler(logger *slog.Logger, tpl *templates.Templates, applications repository.ApplicationRepository, clients repository.ClientRepository, apps *service.AppService, providers *service.ProviderService, operatorAuth *service.OperatorLoginService, sessions *session.OperatorManager) *Handler {
	return &Handler{
		logger:       logger,
		templates:    tpl,
		applications: applications,
		clients:      clients,
		apps:         apps,
		providers:    providers,
		operatorAuth: operatorAuth,
		sessions:     sessions,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/login", h.operatorLoginPageHandler)
	mux.HandleFunc("POST /admin/auth/login", h.operatorLoginHandler)
	mux.HandleFunc("POST /admin/auth/logout", h.operatorLogoutHandler)
	mux.Handle("GET /admin", middleware.RequireOperator(http.HandlerFunc(h.dashboardHandler)))
	mux.Handle("GET /admin/apps", middleware.RequireOperator(http.HandlerFunc(h.appListHandler)))
	mux.Handle("GET /admin/apps/new", middleware.RequireOperator(http.HandlerFunc(h.appNewHandler)))
	mux.Handle("POST /admin/apps", middleware.RequireOperator(http.HandlerFunc(h.appCreateHandler)))
	mux.Handle("GET /admin/apps/{id}", middleware.RequireOperator(http.HandlerFunc(h.appDetailHandler)))
	mux.Handle("GET /admin/apps/{id}/edit", middleware.RequireOperator(http.HandlerFunc(h.appEditHandler)))
	mux.Handle("POST /admin/apps/{id}/edit", middleware.RequireOperator(http.HandlerFunc(h.appUpdateHandler)))
	mux.Handle("GET /admin/apps/{id}/clients/new", middleware.RequireOperator(http.HandlerFunc(h.clientNewHandler)))
	mux.Handle("POST /admin/apps/{id}/clients", middleware.RequireOperator(http.HandlerFunc(h.clientCreateHandler)))
	mux.Handle("GET /admin/clients/{id}", middleware.RequireOperator(http.HandlerFunc(h.clientDetailHandler)))
	mux.Handle("GET /admin/apps/{id}/providers/new", middleware.RequireOperator(http.HandlerFunc(h.providerNewHandler)))
	mux.Handle("POST /admin/apps/{id}/providers", middleware.RequireOperator(http.HandlerFunc(h.providerSaveHandler)))
	mux.Handle("GET /admin/apps/{id}/providers/{provider}/edit", middleware.RequireOperator(http.HandlerFunc(h.providerEditHandler)))
	mux.Handle("POST /admin/apps/{id}/providers/{provider}/toggle", middleware.RequireOperator(http.HandlerFunc(h.providerToggleHandler)))
	mux.Handle("POST /admin/apps/{id}/providers/{provider}/delete", middleware.RequireOperator(http.HandlerFunc(h.providerDeleteHandler)))
}
