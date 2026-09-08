package internal

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/middleware"
	"github.com/adamdlear/centrauth/internal/repository"
	"github.com/adamdlear/centrauth/internal/service"
)

type App struct {
	server    *http.Server
	db        *db.DB
	templates *templates
	login     *service.LoginService
}

//go:embed static/*
var staticFiles embed.FS

func NewApp(cfg AppConfig, database *db.DB) *App {
	if database == nil {
		panic("centrauth: NewApp requires a non-nil database")
	}

	userRepo := repository.NewGormUserRepo(database.Client)
	credRepo := repository.NewGormCredentialRepo(database.Client)

	a := &App{
		db:        database,
		templates: newTemplates(),
		login:     service.NewLoginService(userRepo, credRepo),
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
	mux.Handle("GET /static/", http.StripPrefix("/static/", fileServer))

	return middleware.Logger(mux)
}

func (a *App) Run(ctx context.Context) error {
	errChan := make(chan error, 1)

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
