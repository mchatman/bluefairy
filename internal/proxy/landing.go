package proxy

import (
	"net/http"
	"strings"

	"github.com/mchatman/bluefairy/internal/auth"
)

// LandingHandler serves the login page at GET /.
// If the user has a valid aware_token cookie, it redirects to /chat/.
// It also handles GET /logout and POST /logout.
type LandingHandler struct {
	JWTSecret string
	IndexHTML []byte // loaded from public/index.html at startup
}

func (h *LandingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/logout" && r.Method == http.MethodGet:
		h.serveLogoutPage(w, r)
	case r.URL.Path == "/logout" && r.Method == http.MethodPost:
		h.handlePostLogout(w, r)
	case r.URL.Path == "/":
		h.serveLanding(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveLanding handles GET /.
// If there's an ?error param, always show the login page.
// Otherwise, check for a valid token and redirect to /chat/.
func (h *LandingHandler) serveLanding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// If there's an error parameter, always show the login page.
	if r.URL.Query().Get("error") == "" {
		// Check for existing valid session.
		if c, err := r.Cookie("aware_token"); err == nil && c.Value != "" {
			if _, err := auth.VerifyAccessToken(h.JWTSecret, c.Value); err == nil {
				http.Redirect(w, r, "/chat/", http.StatusFound)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.IndexHTML)
}

// serveLogoutPage serves a small HTML page that clears client-side state
// and redirects to /.
func (h *LandingHandler) serveLogoutPage(w http.ResponseWriter, _ *http.Request) {
	// Clear the cookie server-side as well.
	http.SetCookie(w, &http.Cookie{
		Name:     "aware_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = w.Write([]byte(logoutHTML))
}

// handlePostLogout clears the cookie and redirects to /.
func (h *LandingHandler) handlePostLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "aware_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// logoutHTML is the page served at GET /logout. It clears localStorage and the
// cookie, then redirects to the landing page.
var logoutHTML = strings.TrimSpace(`
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Logging out…</title></head>
<body>
<p>Logging out…</p>
<script>
try { localStorage.removeItem('aware_refresh_token'); } catch(e) {}
try { localStorage.removeItem('aware.control.settings.v1'); } catch(e) {}
document.cookie = 'aware_token=; path=/; max-age=0; SameSite=Lax';
window.location.href = '/';
</script>
</body>
</html>
`)
