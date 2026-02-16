package proxy

import (
	"log"
	"net/http"
	"net/url"

	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/tenant"
)

// Handler is the API-side reverse proxy that forwards authenticated requests
// to the caller's tenant instance. It is mounted behind auth middleware on
// the /api/* and /gateway/* routes.
type Handler struct {
	tenantClient *tenant.Client
	proxySecret  string
}

// NewHandler creates a Handler that proxies requests to tenant instances
// resolved via the given Resolver. The proxySecret is forwarded as
// X-Proxy-Secret to tenant backends for request verification.
func NewHandler(proxySecret string, tenants *tenant.Client) (*Handler, error) {
	return &Handler{
		tenantClient: tenants,
		proxySecret:  proxySecret,
	}, nil
}

// HandleProxy proxies authenticated requests to the user's tenant instance.
// It looks up the existing instance — it does NOT create one. Instance
// creation only happens at signup.
func (h *Handler) HandleProxy(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	instance, err := h.tenantClient.GetInstance(r.Context(), claims.Subject)
	if err != nil {
		log.Printf("[proxy] failed to look up tenant instance for user %s: %v", claims.Subject, err)
		http.Error(w, "Failed to locate instance", http.StatusServiceUnavailable)
		return
	}
	if instance == nil {
		http.Error(w, "No workspace provisioned. Please log in again.", http.StatusNotFound)
		return
	}

	target, err := url.Parse(instance.Endpoint)
	if err != nil {
		log.Printf("[proxy] invalid tenant endpoint %s: %v", instance.Endpoint, err)
		http.Error(w, "Invalid tenant endpoint", http.StatusInternalServerError)
		return
	}

	proxy := newTenantProxy(proxyOpts{
		Target:      target,
		Instance:    instance,
		UserID:      claims.Subject,
		UserEmail:   claims.Email,
		ProxySecret: h.proxySecret,
		StripPrefix: "/api",
	})

	proxy.ServeHTTP(w, r)
}

// HandleWorkspace proxies all requests under /workspace/ to the tenant,
// including WebSocket upgrades. Used by the aware-web iframe.
//
// Authentication: accepts JWT from the Authorization header, "token" query
// parameter, or "token" cookie. The query-param path is needed because the
// iframe is on a different origin (dashboard.wareit.ai) and can't send
// cookies to api.wareit.ai.
//
// On the first request (authenticated via ?token= query param), a session
// cookie is set so that subsequent requests (asset loads, XHR, WebSocket)
// within the iframe are also authenticated without needing the token in
// every URL.
func (h *Handler) HandleWorkspace(w http.ResponseWriter, r *http.Request) {
	// If authenticated via query param, set a cookie for subsequent requests.
	if tokenParam := r.URL.Query().Get("token"); tokenParam != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    tokenParam,
			Path:     "/workspace/",
			MaxAge:   15 * 60, // 15 min (matches JWT TTL)
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		})
	}

	claims := auth.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	instance, err := h.tenantClient.GetInstance(r.Context(), claims.Subject)
	if err != nil {
		log.Printf("[workspace] failed to look up tenant for user %s: %v", claims.Subject, err)
		http.Error(w, "Failed to locate instance", http.StatusServiceUnavailable)
		return
	}
	if instance == nil {
		http.Error(w, "No workspace provisioned", http.StatusNotFound)
		return
	}

	target, err := url.Parse(instance.Endpoint)
	if err != nil {
		log.Printf("[workspace] invalid tenant endpoint %s: %v", instance.Endpoint, err)
		http.Error(w, "Invalid tenant endpoint", http.StatusInternalServerError)
		return
	}

	// WebSocket upgrades need hijack+splice.
	if isWebSocketUpgrade(r) {
		proxyWebSocket(w, r, target, target.Host, instance.Token, claims.Subject, claims.Email, h.proxySecret)
		return
	}

	proxy := newTenantProxy(proxyOpts{
		Target:      target,
		Instance:    instance,
		UserID:      claims.Subject,
		UserEmail:   claims.Email,
		ProxySecret: h.proxySecret,
		StripPrefix: "/workspace",
	})

	proxy.ServeHTTP(w, r)
}
