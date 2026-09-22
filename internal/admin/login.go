package admin

import (
	"errors"
	"net/http"

	"github.com/adamdlear/centrauth/internal/middleware"
	"github.com/adamdlear/centrauth/internal/service"
)

type operatorLoginPageData struct {
	Title string
	Error string
}

func (h *Handler) operatorLoginPageHandler(w http.ResponseWriter, r *http.Request) {
	if middleware.OperatorFromContext(r.Context()) != nil {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	h.renderOperatorLogin(w, operatorLoginPageData{Title: "Operator Sign In"})
}

func (h *Handler) operatorLoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if middleware.OperatorFromContext(ctx) != nil {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	pwd := r.FormValue("password")

	operator, err := h.operatorAuth.VerifyOperatorWithEmailAndPassword(ctx, email, pwd)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			h.logger.Warn("operator login failed")
			h.renderOperatorLogin(w, operatorLoginPageData{Title: "Operator Sign In", Error: "Invalid email or password"})
			return
		}
		h.logger.Error("operator login failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	token, err := h.sessions.Create(ctx, operator.ID)
	if err != nil {
		h.logger.Error("failed to create operator session", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	h.sessions.SetCookie(w, token)

	h.logger.Info("operator login succeeded", "operator_id", operator.ID)

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handler) operatorLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := h.sessions.GetCookie(r); err == nil {
		if s, verr := h.sessions.Validate(r.Context(), cookie.Value); verr == nil {
			_ = h.sessions.Revoke(r.Context(), s.ID)
		}
	}
	h.sessions.ClearCookie(w)

	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (h *Handler) renderOperatorLogin(w http.ResponseWriter, data operatorLoginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.OperatorLogin.ExecuteTemplate(w, "operator_login.html", data); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
