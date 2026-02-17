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
// resolved via the given tenant client.
func NewHandler(proxySecret string, tenants *tenant.Client) (*Handler, error) {
	return &Handler{
		tenantClient: tenants,
		proxySecret:  proxySecret,
	}, nil
}

// HandleProxy proxies authenticated requests to the user's tenant instance.
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
