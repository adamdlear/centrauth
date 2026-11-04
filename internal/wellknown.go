package internal

import (
	"encoding/json"
	"net/http"
)

func (a *App) jwksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(a.keyManager.JWKS())
}

func (a *App) discoveryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if err := json.NewEncoder(w).Encode(a.discovery); err != nil {
		a.logger.Error("failed to encode discovery document", "error", err)
	}
}
