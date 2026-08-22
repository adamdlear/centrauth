package internal

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/adamdlear/centrauth/internal/db"
	"github.com/adamdlear/centrauth/internal/middleware"
)

type App struct {
	server *http.Server
	db     *db.DB
}

func NewApp(cfg AppConfig, database *db.DB) *App {
	a := &App{db: database}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", a.healthHandler)

	handler := middleware.Logger(mux)

	a.server = &http.Server{
		Addr:         cfg.ServerConfig.Addr,
		Handler:      handler,
		ReadTimeout:  cfg.ServerConfig.ReadTimeout,
		WriteTimeout: cfg.ServerConfig.WriteTimeout,
		IdleTimeout:  cfg.ServerConfig.IdleTimeout,
	}

	return a
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
		if a.db != nil {
			return a.db.Close()
		}
		return nil
	}
}
