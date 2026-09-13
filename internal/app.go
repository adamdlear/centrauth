package internal

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/middleware"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/service"
	"github.com/adamdlear/centrauth/internal/session"
)

type App struct {
	logger    *slog.Logger
	server    *http.Server
	db        *db.DB
	templates *templates
	login     *service.LoginService
	sessions  *session.Manager
	users     repository.UserRepository
}

//go:embed static/*
var staticFiles embed.FS

func NewApp(cfg AppConfig, database *db.DB) *App {
	if database == nil {
		panic("centrauth: NewApp requires a non-nil database")
	}

	userRepo := repository.NewGormUserRepo(database.Client)
	credRepo := repository.NewGormCredentialRepo(database.Client)
	sessionRepo := repository.NewGormSessionRepo(database.Client)

	a := &App{
		logger:    slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})),
		db:        database,
		templates: newTemplates(),
		login:     service.NewLoginService(userRepo, credRepo),
		sessions:  session.NewManager(sessionRepo, cfg.SessionConfig),
		users:     userRepo,
	}

	a.server = &http.Server{
		Addr:         cfg.ServerConfig.Addr,
		Handler:      a.routes(),
		ReadTimeout:  cfg.ServerConfig.ReadTimeout,
		WriteTimeout: cfg.ServerConfig.WriteTimeout,
		IdleTimeout:  cfg.ServerConfig.IdleTimeout,
	}

	return a
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()

	staticFS, _ := fs.Sub(staticFiles, "static")
	fileServer := http.FileServer(http.FS(staticFS))

	mux.HandleFunc("GET /healthz", a.healthHandler)
	mux.HandleFunc("GET /login", a.loginPageHandler)
	mux.HandleFunc("POST /auth/login", a.loginHandler)
	mux.HandleFunc("POST /auth/register", a.registerHandler)
	mux.HandleFunc("POST /auth/logout", a.logoutHandler)
	mux.HandleFunc("GET /", a.rootHandler)
	mux.Handle("GET /dashboard", middleware.RequireAuth(http.HandlerFunc(a.dashboardHandler)))
	mux.Handle("GET /static/", http.StripPrefix("/static/", fileServer))

	var handler http.Handler = mux
	handler = middleware.Session(handler, a.sessions, a.users)
	handler = middleware.CSRF(handler)
	handler = middleware.Logger(handler)

	return handler
}

func (a *App) Run(ctx context.Context) error {
	errChan := make(chan error, 1)

	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				count, err := a.sessions.DeleteInactive(ctx)
				if err != nil {
					a.logger.Error("failed to delete expired sessions", "error", err)
				}
				a.logger.Debug("deleted expired sessions", "count", count)
			}
		}
	}()

	go func() {
		errChan <- a.server.ListenAndServe()
	}()

	select {
	case err := <-errChan:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := a.server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return a.db.Close()
	}
}
