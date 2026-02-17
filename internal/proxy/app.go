package proxy

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/config"
	"github.com/mchatman/bluefairy/internal/tenant"
)

const refreshCookieName = "aware_refresh"

// AppHandler routes requests on dashboard.wareit.ai to either
// aware-web (Vercel) for UI pages or the tenant for the workspace.
// This keeps everything on one domain with no iframe or cross-origin issues.
type AppHandler struct {
	cfg          *config.Config
	authHandler  *auth.Handler
	tenantClient *tenant.Client
	frontendURL  *url.URL
}

// NewAppHandler creates the unified dashboard handler.
// frontendURL is the aware-web deployment URL (e.g. the *.vercel.app URL).
func NewAppHandler(cfg *config.Config, authHandler *auth.Handler, tenants *tenant.Client, frontendURL string) *AppHandler {
	u, err := url.Parse(frontendURL)
	if err != nil {
		log.Fatalf("[app] invalid FRONTEND_URL %q: %v", frontendURL, err)
	}
	return &AppHandler{cfg: cfg, authHandler: authHandler, tenantClient: tenants, frontendURL: u}
}

func (h *AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Always proxy these paths to aware-web (frontend assets + API routes).
	if h.isFrontendPath(path) {
		h.proxyToFrontend(w, r)
		return
	}

	// Root path: unauthenticated → login page, authenticated → workspace.
	if path == "/" && !h.hasValidToken(r) {
		h.proxyToFrontend(w, r)
		return
	}

	// Everything else (including WebSocket): proxy to tenant.
	h.proxyToTenant(w, r)
}

// isFrontendPath returns true for paths that should always go to aware-web.
func (h *AppHandler) isFrontendPath(path string) bool {
	switch {
	case path == "/dashboard",
		path == "/signup",
		path == "/logout":
		return true
	case strings.HasPrefix(path, "/_next/"),
		strings.HasPrefix(path, "/api/"):
		return true
	case path == "/favicon.ico":
		return true
	}
	return false
}

// hasValidToken checks if the request has a valid or refreshable session.
func (h *AppHandler) hasValidToken(r *http.Request) bool {
	if c, err := r.Cookie("token"); err == nil && c.Value != "" {
		if _, err := auth.VerifyAccessToken(h.cfg.JWTSecret, c.Value); err == nil {
			return true
		}
	}
	// Access token missing or expired — check if there's a refresh token.
	if c, err := r.Cookie(refreshCookieName); err == nil && c.Value != "" {
		return true
	}
	return false
}

// tryRefresh attempts to transparently refresh an expired JWT using the
// refresh token cookie. On success it sets new cookies and returns claims.
func (h *AppHandler) tryRefresh(w http.ResponseWriter, r *http.Request) (*auth.JWTClaims, error) {
	rc, err := r.Cookie(refreshCookieName)
	if err != nil || rc.Value == "" {
		return nil, fmt.Errorf("no refresh cookie")
	}

	_, tokens, err := h.authHandler.RefreshToken(r.Context(), rc.Value)
	if err != nil {
		return nil, fmt.Errorf("refresh failed: %w", err)
	}

	// Set new cookies.
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokens.AccessToken,
		Path:     "/",
		MaxAge:   7 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    tokens.RefreshToken,
		Path:     "/",
		MaxAge:   h.cfg.RefreshTokenTTLDays * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	claims, err := auth.VerifyAccessToken(h.cfg.JWTSecret, tokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("verify fresh token: %w", err)
	}

	log.Printf("[app] transparently refreshed JWT for user %s", claims.Subject)
	return claims, nil
}

// proxyToFrontend reverse-proxies the request to aware-web on Vercel.
func (h *AppHandler) proxyToFrontend(w http.ResponseWriter, r *http.Request) {
	proxy := httputil.NewSingleHostReverseProxy(h.frontendURL)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = h.frontendURL.Host
	}
	proxy.ServeHTTP(w, r)
}

// proxyToTenant authenticates the user and proxies to their tenant instance.
// If the access token is expired, it transparently refreshes using the
// refresh token cookie before proxying.
func (h *AppHandler) proxyToTenant(w http.ResponseWriter, r *http.Request) {
	// Read JWT from cookie.
	c, err := r.Cookie("token")
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	claims, err := auth.VerifyAccessToken(h.cfg.JWTSecret, c.Value)
	if err != nil {
		// Token expired — try transparent refresh.
		claims, err = h.tryRefresh(w, r)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	instance, err := h.tenantClient.GetInstance(r.Context(), claims.Subject)
	if err != nil {
		log.Printf("[app] tenant lookup failed for user %s: %v", claims.Subject, err)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	if instance == nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	target, err := url.Parse(instance.Endpoint)
	if err != nil {
		log.Printf("[app] invalid tenant endpoint %s: %v", instance.Endpoint, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// WebSocket upgrades use hijack+splice.
	if isWebSocketUpgrade(r) {
		proxyWebSocket(w, r, target, target.Host, instance.Token, claims.Subject, claims.Email, h.cfg.ProxySecret)
		return
	}

	// Regular HTTP — reverse proxy to tenant.
	proxy := newTenantProxy(proxyOpts{
		Target:      target,
		Instance:    instance,
		UserID:      claims.Subject,
		UserEmail:   claims.Email,
		ProxySecret: h.cfg.ProxySecret,
	})

	// If the tenant returns an error (pod not ready, ingress 404, etc.),
	// redirect back to the loading screen instead of showing a raw error.
	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode == http.StatusNotFound ||
			resp.StatusCode == http.StatusBadGateway ||
			resp.StatusCode == http.StatusServiceUnavailable ||
			resp.StatusCode == http.StatusGatewayTimeout {
			log.Printf("[app] tenant returned %d for user %s, redirecting to loading", resp.StatusCode, claims.Subject)
			resp.StatusCode = http.StatusFound
			resp.Header.Set("Location", "/dashboard")
			resp.Header.Set("Content-Length", "0")
			resp.Body.Close()
			resp.Body = http.NoBody
			resp.ContentLength = 0
		}
		return nil
	}

	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("[app] proxy error for user %s: %v", claims.Subject, err)
		http.Redirect(rw, req, "/dashboard", http.StatusFound)
	}

	proxy.ServeHTTP(w, r)
}
