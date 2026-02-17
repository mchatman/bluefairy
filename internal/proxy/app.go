package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/config"
	"github.com/mchatman/bluefairy/internal/tenant"
)

// AppHandler routes requests on dashboard.wareit.ai to either
// aware-web (Vercel) for UI pages or the tenant for the workspace.
// This keeps everything on one domain with no iframe or cross-origin issues.
type AppHandler struct {
	cfg          *config.Config
	tenantClient *tenant.Client
	frontendURL  *url.URL
}

// NewAppHandler creates the unified dashboard handler.
// frontendURL is the aware-web deployment URL (e.g. the *.vercel.app URL).
func NewAppHandler(cfg *config.Config, tenants *tenant.Client, frontendURL string) *AppHandler {
	u, err := url.Parse(frontendURL)
	if err != nil {
		log.Fatalf("[app] invalid FRONTEND_URL %q: %v", frontendURL, err)
	}
	return &AppHandler{cfg: cfg, tenantClient: tenants, frontendURL: u}
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

// hasValidToken checks if the request has a valid JWT in the token cookie.
func (h *AppHandler) hasValidToken(r *http.Request) bool {
	c, err := r.Cookie("token")
	if err != nil || c.Value == "" {
		return false
	}
	_, err = auth.VerifyAccessToken(h.cfg.JWTSecret, c.Value)
	return err == nil
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
func (h *AppHandler) proxyToTenant(w http.ResponseWriter, r *http.Request) {
	// Read JWT from cookie.
	c, err := r.Cookie("token")
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	claims, err := auth.VerifyAccessToken(h.cfg.JWTSecret, c.Value)
	if err != nil {
		// Token expired — try refresh.
		// For now, redirect to login. Transparent refresh can be added later.
		http.Redirect(w, r, "/", http.StatusFound)
		return
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

	proxy.ServeHTTP(w, r)
}
