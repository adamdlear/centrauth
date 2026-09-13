package internal

import "net/http"

func (a *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := a.sessions.GetCookie(r); err == nil {
		if s, verr := a.sessions.Validate(r.Context(), cookie.Value); verr == nil {
			_ = a.sessions.Revoke(r.Context(), s.ID)
		}
	}
	a.sessions.ClearCookie(w)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
