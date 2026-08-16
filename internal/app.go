package internal

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/adamdlear/centrauth/internal/middleware"
)

type App struct {
	server *http.Server
}

func NewApp(cfg AppConfig) *App {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", HealthHandler)

	handler := middleware.Logger(mux)

	return &App{
		server: &http.Server{
			Addr:         cfg.ServerConfig.Addr,
			Handler:      handler,
			ReadTimeout:  cfg.ServerConfig.ReadTimeout,
			WriteTimeout: cfg.ServerConfig.WriteTimeout,
			IdleTimeout:  cfg.ServerConfig.IdleTimeout,
		},
	}
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

		return a.server.Shutdown(shutdownCtx)
	}
}
