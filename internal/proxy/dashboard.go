package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/config"
	"github.com/mchatman/bluefairy/internal/tenant"
	"github.com/mchatman/bluefairy/internal/user"
)

const (
	dashboardCookieName = "aware_dashboard"
	refreshCookieName   = "aware_refresh"
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
	refreshStore *auth.RefreshStore
	userService  *user.Service
	authHandler  *auth.Handler
	loginHTML    []byte
}

func NewDashboardHandler(cfg *config.Config, pool *pgxpool.Pool, userService *user.Service, authHandler *auth.Handler, loginHTML []byte, tenants tenant.Resolver) *DashboardHandler {
	return &DashboardHandler{
		cfg:          cfg,
		jwtSecret:    cfg.JWTSecret,
		tenantClient: tenants,
		refreshStore: auth.NewRefreshStore(pool),
		userService:  userService,
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
		d.authHandler.Refresh(w, r)
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
	if c, err := r.Cookie(dashboardCookieName); err == nil && c.Value != "" {
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
		log.Printf("Invalid callback token: %v", err)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Set HTTP-only cookie for the JWT on this domain
	http.SetCookie(w, &http.Cookie{
		Name:     dashboardCookieName,
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
			Name:     refreshCookieName,
			Value:    rt,
			Path:     "/",
			MaxAge:   d.cfg.RefreshTokenTTLDays * 24 * 60 * 60,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

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

	// Clear the refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Revoke all refresh tokens for the user if we can identify them
	if c, err := r.Cookie(dashboardCookieName); err == nil && c.Value != "" {
		// Try to parse claims even from an expired JWT to get the user ID
		if claims, err := auth.VerifyAccessToken(d.jwtSecret, c.Value); err == nil {
			_ = d.refreshStore.RevokeAllForUser(r.Context(), claims.Subject)
		}
	}
	if c, err := r.Cookie(refreshCookieName); err == nil && c.Value != "" {
		tokenHash := auth.SHA256Hash(c.Value)
		if userID, err := d.refreshStore.Validate(r.Context(), tokenHash); err == nil {
			_ = d.refreshStore.RevokeAllForUser(r.Context(), userID)
		}
	}

	// Redirect to login page
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (d *DashboardHandler) clearAllCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     dashboardCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
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
	cookie, err := r.Cookie(dashboardCookieName)
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

	// Determine the Host header for upstream routing.
	// When TENANT_HOST_TEMPLATE is set (e.g. connecting via LB IP but nginx
	// needs a real hostname), use inst.Host; otherwise use the target URL's host.
	routeHost := target.Host
	if inst.Host != "" {
		routeHost = inst.Host
	}

	// Handle WebSocket upgrades via hijack+splice (httputil.ReverseProxy doesn't support them)
	if isWebSocketUpgrade(r) {
		d.handleWebSocketProxy(w, r, target, routeHost, inst.Token, claims.Subject, claims.Email)
		return
	}

	// Reverse proxy to the tenant
	proxy := httputil.NewSingleHostReverseProxy(target)

	// When connecting via IP to an nginx ingress with a self-signed cert,
	// we need to skip TLS verification and set the SNI server name so
	// the ingress matches the right rule.
	if target.Scheme == "https" && inst.Host != "" {
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         routeHost,
			},
		}
	}

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
		if d.cfg.ProxySecret != "" {
			req.Header.Set("X-Proxy-Secret", d.cfg.ProxySecret)
		}
		req.Host = routeHost
	}

	// Show friendly error page if the tenant is unreachable or starting up
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("[dashboard] proxy error for user %s: %v", claims.Subject, err)
		if wantsHTML(req) {
			serveWorkspaceLoading(rw)
			return
		}
		http.Error(rw, `{"error":"workspace_starting","message":"Your workspace is starting up. Please retry in a few seconds."}`, http.StatusBadGateway)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable {
			// Intercept 502/503 from the backend and replace with friendly page
			resp.Body.Close()
			body := []byte(workspaceLoadingHTML)
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			resp.Header.Set("Retry-After", "5")
			resp.StatusCode = http.StatusBadGateway
		}
		return nil
	}

	proxy.ServeHTTP(w, r)
}

func (d *DashboardHandler) handleWebSocketProxy(w http.ResponseWriter, r *http.Request, target *url.URL, routeHost, gatewayToken, userID, userEmail string) {
	// Determine backend address, adding default port if needed.
	backendAddr := target.Host
	if _, _, err := net.SplitHostPort(backendAddr); err != nil {
		if target.Scheme == "https" || target.Scheme == "wss" {
			backendAddr = net.JoinHostPort(backendAddr, "443")
		} else {
			backendAddr = net.JoinHostPort(backendAddr, "80")
		}
	}

	// Hijack the client connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Server does not support hijacking", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		log.Printf("[dashboard-ws] hijack failed: %v", err)
		return
	}

	// Dial the backend.
	var backendConn net.Conn
	if target.Scheme == "https" || target.Scheme == "wss" {
		// Use routeHost for SNI so nginx ingress matches the right rule.
		// Skip TLS verify since the ingress uses a self-signed cert.
		sni := routeHost
		if h, _, splitErr := net.SplitHostPort(routeHost); splitErr == nil {
			sni = h
		}
		backendConn, err = tls.Dial("tcp", backendAddr, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		})
	} else {
		backendConn, err = net.Dial("tcp", backendAddr)
	}
	if err != nil {
		log.Printf("[dashboard-ws] backend connect failed addr=%s: %v", backendAddr, err)
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nGateway unreachable"))
		clientConn.Close()
		return
	}

	// Build upstream path with query parameters.
	upstreamPath := r.URL.Path
	if upstreamPath == "" {
		upstreamPath = "/"
	}
	q := r.URL.Query()
	if gatewayToken != "" {
		q.Set("token", gatewayToken)
	}
	if encoded := q.Encode(); encoded != "" {
		upstreamPath += "?" + encoded
	}

	// Build the HTTP upgrade request.
	var reqBuf strings.Builder
	reqBuf.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\n", upstreamPath))

	hostWritten := false
	for key, vals := range r.Header {
		lower := strings.ToLower(key)
		switch lower {
		case "host":
			reqBuf.WriteString(fmt.Sprintf("Host: %s\r\n", routeHost))
			hostWritten = true
		case "origin":
			reqBuf.WriteString(fmt.Sprintf("Origin: %s://%s\r\n", target.Scheme, routeHost))
		default:
			for _, v := range vals {
				reqBuf.WriteString(fmt.Sprintf("%s: %s\r\n", key, v))
			}
		}
	}
	if !hostWritten {
		reqBuf.WriteString(fmt.Sprintf("Host: %s\r\n", routeHost))
	}
	reqBuf.WriteString(fmt.Sprintf("X-User-ID: %s\r\n", userID))
	reqBuf.WriteString(fmt.Sprintf("X-User-Email: %s\r\n", userEmail))
	if d.cfg.ProxySecret != "" {
		reqBuf.WriteString(fmt.Sprintf("X-Proxy-Secret: %s\r\n", d.cfg.ProxySecret))
	}
	reqBuf.WriteString("\r\n")

	// Send the upgrade request to the backend.
	_, err = backendConn.Write([]byte(reqBuf.String()))
	if err != nil {
		log.Printf("[dashboard-ws] backend write failed: %v", err)
		backendConn.Close()
		clientConn.Close()
		return
	}

	// Flush any buffered data from the hijacked connection to the backend.
	if clientBuf.Reader.Buffered() > 0 {
		buffered := make([]byte, clientBuf.Reader.Buffered())
		_, _ = clientBuf.Read(buffered)
		_, _ = backendConn.Write(buffered)
	}

	// Bidirectional splice.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, backendConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(backendConn, clientConn)
		if tc, ok := backendConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
	backendConn.Close()
	clientConn.Close()
}

// tryRefresh attempts to transparently refresh an expired JWT using the
// refresh token cookie. On success it sets new dashboard + refresh cookies
// and returns the fresh JWT claims. On failure it returns an error.
func (d *DashboardHandler) tryRefresh(w http.ResponseWriter, r *http.Request) (*auth.JWTClaims, error) {
	rc, err := r.Cookie(refreshCookieName)
	if err != nil || rc.Value == "" {
		return nil, fmt.Errorf("no refresh cookie")
	}

	ctx := r.Context()
	oldHash := auth.SHA256Hash(rc.Value)

	// Validate old refresh token
	userID, err := d.refreshStore.Validate(ctx, oldHash)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Revoke old refresh token (rotation)
	_ = d.refreshStore.Revoke(ctx, oldHash)

	// Look up the user
	usr, err := d.userService.GetUser(ctx, userID)
	if err != nil || usr == nil {
		return nil, fmt.Errorf("user lookup failed")
	}

	// Issue new JWT
	token, err := auth.SignAccessToken(d.jwtSecret, usr.ID, usr.Email, "free", d.cfg.AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	// Issue new refresh token
	newRaw := auth.GenerateOpaqueToken()
	newHash := auth.SHA256Hash(newRaw)
	refreshExpiry := time.Now().Add(time.Duration(d.cfg.RefreshTokenTTLDays) * 24 * time.Hour)
	if err := d.refreshStore.Create(ctx, usr.ID, newHash, refreshExpiry); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	// Set new cookies
	http.SetCookie(w, &http.Cookie{
		Name:     dashboardCookieName,
		Value:    token.AccessToken,
		Path:     "/",
		MaxAge:   7 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    newRaw,
		Path:     "/",
		MaxAge:   d.cfg.RefreshTokenTTLDays * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Parse back the fresh claims
	claims, err := auth.VerifyAccessToken(d.jwtSecret, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("verify fresh token: %w", err)
	}

	log.Printf("Transparently refreshed JWT for user %s", usr.ID)
	return claims, nil
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
func serveWorkspaceLoading(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Retry-After", "5")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write([]byte(workspaceLoadingHTML))
}

// workspaceLoadingHTML is the friendly page shown when the tenant pod is
// starting up or temporarily unreachable.
var workspaceLoadingHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Starting your workspace…</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       background:#0a0a0f;color:#e0e0e0;display:flex;align-items:center;
       justify-content:center;min-height:100vh;text-align:center}
  .card{max-width:420px;padding:2.5rem}
  h1{font-size:1.4rem;font-weight:600;margin-bottom:.75rem}
  p{color:#888;font-size:.95rem;line-height:1.5;margin-bottom:1.5rem}
  .spinner{width:40px;height:40px;margin:0 auto 1.5rem;
           border:3px solid #222;border-top-color:#6c63ff;border-radius:50%;
           animation:spin .8s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .retry{color:#6c63ff;font-size:.85rem}
</style>
</head>
<body>
<div class="card">
  <div class="spinner"></div>
  <h1>Starting your workspace</h1>
  <p>This usually takes just a few seconds. The page will refresh automatically.</p>
  <div class="retry">Retrying…</div>
</div>
<script>setTimeout(function(){location.reload()},5000)</script>
</body>
</html>`
