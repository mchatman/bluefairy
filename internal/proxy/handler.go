package proxy

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/tenant"
)

type Handler struct {
	tenantClient tenant.Resolver
	proxySecret  string
}

func NewHandler(proxySecret string, tenants tenant.Resolver) (*Handler, error) {
	return &Handler{
		tenantClient: tenants,
		proxySecret:  proxySecret,
	}, nil
}

// HandleProxy proxies authenticated requests to the user's tenant instance.
// It looks up the existing instance — it does NOT create one. Instance
// creation only happens at signup.
func (h *Handler) HandleProxy(w http.ResponseWriter, r *http.Request) {
	// Get claims from context (set by auth middleware)
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Look up existing tenant instance — never create on a proxy request
	instance, err := h.tenantClient.GetInstanceFromOrchestrator(r.Context(), claims.Subject)
	if err != nil {
		log.Printf("Failed to look up tenant instance for user %s: %v", claims.Subject, err)
		http.Error(w, "Failed to locate instance", http.StatusServiceUnavailable)
		return
	}
	if instance == nil {
		http.Error(w, "No workspace provisioned. Please log in again.", http.StatusNotFound)
		return
	}

	// Parse the tenant endpoint URL
	target, err := url.Parse(instance.Endpoint)
	if err != nil {
		log.Printf("Invalid tenant endpoint %s: %v", instance.Endpoint, err)
		http.Error(w, "Invalid tenant endpoint", http.StatusInternalServerError)
		return
	}

	// Determine Host header for upstream routing (when using IP-based endpoints
	// with nginx ingress, the real hostname is needed for ingress matching).
	routeHost := target.Host
	if instance.Host != "" {
		routeHost = instance.Host
	}

	// Create a reverse proxy for this specific request
	proxy := httputil.NewSingleHostReverseProxy(target)

	// When connecting via IP to an nginx ingress with a self-signed cert,
	// skip TLS verification and set SNI for correct ingress matching.
	if target.Scheme == "https" && instance.Host != "" {
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         routeHost,
			},
		}
	}

	// Customize the director to add auth and routing
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Strip /api prefix if present
		req.URL.Path = strings.TrimPrefix(req.URL.Path, "/api")

		// Add gateway token to URL query params
		q := req.URL.Query()
		q.Set("token", instance.Token)
		req.URL.RawQuery = q.Encode()

		// Add user context as headers for the backend
		req.Header.Set("X-User-ID", claims.Subject)
		req.Header.Set("X-User-Email", claims.Email)
		if h.proxySecret != "" {
			req.Header.Set("X-Proxy-Secret", h.proxySecret)
		}
		req.Host = routeHost
	}

	// Proxy the request
	proxy.ServeHTTP(w, r)
}
