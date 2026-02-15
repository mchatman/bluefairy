package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/tenant"
)

const dashboardCookieName = "aware_dashboard"

// DashboardHandler serves the tenant proxy on dashboard.wareit.ai.
// It handles:
//   - /auth/callback?token=JWT  — sets cookie, redirects to /
//   - /logout                   — clears cookie, redirects to login
//   - /*                        — validates cookie, proxies to tenant
type DashboardHandler struct {
	jwtSecret    string
	tenantClient *tenant.Client
	loginURL     string // e.g. https://aware-web-tawny.vercel.app
}

func NewDashboardHandler(jwtSecret string, loginURL string) *DashboardHandler {
	return &DashboardHandler{
		jwtSecret:    jwtSecret,
		tenantClient: tenant.NewClient(),
		loginURL:     loginURL,
	}
}

func (d *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/auth/callback":
		d.handleCallback(w, r)
	case path == "/logout":
		d.handleLogout(w, r)
	default:
		d.handleProxy(w, r)
	}
}

func (d *DashboardHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		http.Redirect(w, r, d.loginURL, http.StatusFound)
		return
	}

	// Validate the JWT
	claims, err := auth.VerifyAccessToken(d.jwtSecret, tokenStr)
	if err != nil {
		log.Printf("Invalid callback token: %v", err)
		http.Redirect(w, r, d.loginURL, http.StatusFound)
		return
	}

	// Set HTTP-only cookie on this domain
	http.SetCookie(w, &http.Cookie{
		Name:     dashboardCookieName,
		Value:    tokenStr,
		Path:     "/",
		MaxAge:   7 * 24 * 60 * 60, // 7 days
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Look up the tenant to get the gateway token for WebSocket auth
	inst, err := d.tenantClient.GetInstanceFromOrchestrator(r.Context(), claims.Subject)
	if err != nil || inst == nil || inst.Token == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Redirect with gateway token so the OpenClaw SPA stores it for WebSocket auth
	http.Redirect(w, r, "/?token="+inst.Token, http.StatusFound)
}

func (d *DashboardHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear the dashboard cookie
	http.SetCookie(w, &http.Cookie{
		Name:     dashboardCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to aware-web's logout to clear its cookie too
	http.Redirect(w, r, d.loginURL+"/logout", http.StatusFound)
}

func (d *DashboardHandler) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Read JWT from cookie
	cookie, err := r.Cookie(dashboardCookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, d.loginURL, http.StatusFound)
		return
	}

	claims, err := auth.VerifyAccessToken(d.jwtSecret, cookie.Value)
	if err != nil {
		// Token expired or invalid — clear cookie and redirect to login
		http.SetCookie(w, &http.Cookie{
			Name:   dashboardCookieName,
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		http.Redirect(w, r, d.loginURL, http.StatusFound)
		return
	}

	// Look up tenant instance
	inst, err := d.tenantClient.GetInstanceFromOrchestrator(r.Context(), claims.Subject)
	if err != nil {
		log.Printf("Failed to look up tenant for user %s: %v", claims.Subject, err)
		http.Error(w, "Failed to load your workspace", http.StatusBadGateway)
		return
	}
	if inst == nil {
		http.Error(w, "No workspace found. Please contact support.", http.StatusNotFound)
		return
	}

	// Parse the tenant endpoint
	target, err := url.Parse(inst.Endpoint)
	if err != nil {
		log.Printf("Invalid tenant endpoint %s: %v", inst.Endpoint, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Reverse proxy to the tenant
	proxy := httputil.NewSingleHostReverseProxy(target)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Inject gateway token for authentication
		if inst.Token != "" {
			q := req.URL.Query()
			q.Set("token", inst.Token)
			req.URL.RawQuery = q.Encode()
		}

		req.Header.Set("X-User-ID", claims.Subject)
		req.Header.Set("X-User-Email", claims.Email)
		req.Host = target.Host
	}

	// Handle WebSocket upgrades
	if isWebSocketUpgrade(r) {
		proxy.ModifyResponse = nil
	}

	proxy.ServeHTTP(w, r)
}

func isWebSocketUpgrade(r *http.Request) bool {
	for _, v := range r.Header["Connection"] {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}
