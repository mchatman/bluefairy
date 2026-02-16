package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/config"
	"github.com/mchatman/bluefairy/internal/proxy/static"
	"github.com/mchatman/bluefairy/internal/tenant"
)

// DashboardHandler serves the tenant proxy on dashboard.wareit.ai.
// It handles:
//   - /login                    — serves the login/signup page
//   - /auth/login, /auth/signup — proxies to the auth API
//   - /auth/refresh             — proxies to the auth API
//   - /auth/callback?token=JWT  — sets cookies, redirects to /
//   - /logout                   — clears cookies, shows logout page
//   - /*                        — validates cookie, proxies to tenant
type DashboardHandler struct {
	cfg          *config.Config
	jwtSecret    string
	tenantClient tenant.Resolver
	authHandler  *auth.Handler
	loginHTML    []byte
}

// NewDashboardHandler creates a DashboardHandler that serves the tenant dashboard UI.
// The loginHTML parameter should be the embedded login page (typically static.LoginHTML).
func NewDashboardHandler(cfg *config.Config, authHandler *auth.Handler, loginHTML []byte, tenants tenant.Resolver) *DashboardHandler {
	return &DashboardHandler{
		cfg:          cfg,
		jwtSecret:    cfg.JWTSecret,
		tenantClient: tenants,
		authHandler:  authHandler,
		loginHTML:    loginHTML,
	}
}

func (d *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/login":
		d.serveLoginPage(w, r)
	case path == "/auth/login" && r.Method == http.MethodPost:
		d.authHandler.Login(w, r)
	case path == "/auth/signup" && r.Method == http.MethodPost:
		d.authHandler.Signup(w, r)
	case path == "/auth/refresh" && r.Method == http.MethodPost:
		d.authHandler.HandleRefreshToken(w, r)
	case path == "/auth/callback":
		d.handleCallback(w, r)
	case path == "/logout":
		d.handleLogout(w, r)
	default:
		d.handleProxy(w, r)
	}
}

// serveLoginPage serves the embedded login/signup page.
func (d *DashboardHandler) serveLoginPage(w http.ResponseWriter, r *http.Request) {
	// If user already has a valid session, redirect to dashboard
	if c, err := r.Cookie(DashboardCookieName); err == nil && c.Value != "" {
		if _, err := auth.VerifyAccessToken(d.jwtSecret, c.Value); err == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		// JWT expired — try refresh before showing login
		if _, err := d.tryRefresh(w, r); err == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(d.loginHTML)
}

func (d *DashboardHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Validate the JWT
	claims, err := auth.VerifyAccessToken(d.jwtSecret, tokenStr)
	if err != nil {
		log.Printf("[dashboard] invalid callback token: %v", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Set HTTP-only cookie for the JWT on this domain
	http.SetCookie(w, &http.Cookie{
		Name:     DashboardCookieName,
		Value:    tokenStr,
		Path:     "/",
		MaxAge:   7 * 24 * 60 * 60, // 7 days
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Also set refresh token cookie if provided in the callback URL
	if rt := r.URL.Query().Get("refresh_token"); rt != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     RefreshCookieName,
			Value:    rt,
			Path:     "/",
			MaxAge:   d.cfg.RefreshTokenTTLDays * 24 * 60 * 60,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	// Look up the tenant to get the gateway token for WebSocket auth
	inst, err := d.tenantClient.GetInstance(r.Context(), claims.Subject)
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
		Name:     DashboardCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Clear the refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Revoke all refresh tokens for the user if we can identify them
	if c, err := r.Cookie(DashboardCookieName); err == nil && c.Value != "" {
		if claims, err := auth.VerifyAccessToken(d.jwtSecret, c.Value); err == nil {
			_ = d.authHandler.RevokeAllTokens(r.Context(), claims.Subject)
		}
	}
	if c, err := r.Cookie(RefreshCookieName); err == nil && c.Value != "" {
		// If we couldn't get the user from the JWT, try via refresh token rotation
		if usr, _, err := d.authHandler.RefreshToken(r.Context(), c.Value); err == nil {
			_ = d.authHandler.RevokeAllTokens(r.Context(), usr.ID)
		}
	}

	// Redirect to login page
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (d *DashboardHandler) clearAllCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     DashboardCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (d *DashboardHandler) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Read JWT from cookie
	cookie, err := r.Cookie(DashboardCookieName)
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	claims, err := auth.VerifyAccessToken(d.jwtSecret, cookie.Value)
	if err != nil {
		// JWT is invalid/expired — attempt transparent refresh
		claims, err = d.tryRefresh(w, r)
		if err != nil {
			// Refresh failed — clear everything and redirect to login
			d.clearAllCookies(w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
	}

	// Look up tenant instance
	inst, err := d.tenantClient.GetInstance(r.Context(), claims.Subject)
	if err != nil {
		log.Printf("[dashboard] failed to look up tenant for user %s: %v", claims.Subject, err)
		serveWorkspaceLoading(w)
		return
	}
	if inst == nil {
		http.Error(w, "No workspace found. Please contact support.", http.StatusNotFound)
		return
	}

	// Parse the tenant endpoint
	target, err := url.Parse(inst.Endpoint)
	if err != nil {
		log.Printf("[dashboard] invalid tenant endpoint %s: %v", inst.Endpoint, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	host := routeHost(target, inst)

	// Handle WebSocket upgrades via hijack+splice (httputil.ReverseProxy doesn't support them)
	if isWebSocketUpgrade(r) {
		proxyWebSocket(w, r, target, host, inst.Token, claims.Subject, claims.Email, d.cfg.ProxySecret)
		return
	}

	// Reverse proxy to the tenant
	proxy := newTenantProxy(proxyOpts{
		Target:      target,
		Instance:    inst,
		RouteHost:   host,
		UserID:      claims.Subject,
		UserEmail:   claims.Email,
		ProxySecret: d.cfg.ProxySecret,
	})

	// Show friendly error page if the tenant is unreachable or starting up.
	// IMPORTANT: Do NOT return 502/503 — App Platform intercepts those
	// and replaces our response with its own error page.
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("[dashboard] proxy error for user %s: %v", claims.Subject, err)
		if wantsHTML(req) {
			serveWorkspaceLoading(rw)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Retry-After", "5")
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte(`{"error":"workspace_starting","message":"Your workspace is starting up. Please retry in a few seconds."}`))
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		// Intercept error responses from the backend (nginx ingress) and
		// replace with a friendly loading page. This covers:
		// - 404: ingress rule not yet created (new signup, operator still provisioning)
		// - 502/503: pod not ready or starting up
		// Use 200 to prevent App Platform from replacing our response.
		if resp.StatusCode == http.StatusNotFound ||
			resp.StatusCode == http.StatusBadGateway ||
			resp.StatusCode == http.StatusServiceUnavailable {
			resp.Body.Close()
			body := static.LoadingHTML
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			resp.Header.Set("Retry-After", "5")
			resp.StatusCode = http.StatusOK
		}
		return nil
	}

	proxy.ServeHTTP(w, r)
}



// tryRefresh attempts to transparently refresh an expired JWT using the
// refresh token cookie. On success it sets new dashboard + refresh cookies
// and returns the fresh JWT claims. On failure it returns an error.
func (d *DashboardHandler) tryRefresh(w http.ResponseWriter, r *http.Request) (*auth.JWTClaims, error) {
	rc, err := r.Cookie(RefreshCookieName)
	if err != nil || rc.Value == "" {
		return nil, fmt.Errorf("no refresh cookie")
	}

	usr, tokens, err := d.authHandler.RefreshToken(r.Context(), rc.Value)
	if err != nil {
		return nil, fmt.Errorf("refresh failed: %w", err)
	}

	// Set new cookies
	http.SetCookie(w, &http.Cookie{
		Name:     DashboardCookieName,
		Value:    tokens.AccessToken,
		Path:     "/",
		MaxAge:   7 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookieName,
		Value:    tokens.RefreshToken,
		Path:     "/",
		MaxAge:   d.cfg.RefreshTokenTTLDays * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	claims, err := auth.VerifyAccessToken(d.jwtSecret, tokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("verify fresh token: %w", err)
	}

	log.Printf("[dashboard] transparently refreshed JWT for user %s", usr.ID)
	return claims, nil
}

// wantsHTML returns true if the request prefers an HTML response.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func isWebSocketUpgrade(r *http.Request) bool {
	for _, v := range r.Header["Connection"] {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}

// serveWorkspaceLoading writes the friendly "loading" page as a full response.
// Uses 200 instead of 502 to prevent App Platform from intercepting the response.
func serveWorkspaceLoading(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Retry-After", "5")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(static.LoadingHTML)
}
