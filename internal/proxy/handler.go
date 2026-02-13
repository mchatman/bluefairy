package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/tenant"
)

type Handler struct {
	tenantClient *tenant.Client
}

func NewHandler(backendURL string) (*Handler, error) {
	// backendURL parameter kept for backwards compatibility but ignored
	// We now use tenant orchestrator to manage instances

	return &Handler{
		tenantClient: tenant.NewClient(),
	}, nil
}

// generateToken creates a secure random token
func generateToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a timestamp-based token if random generation fails
		return fmt.Sprintf("fallback-token-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// HandleProxy proxies authenticated requests to the user's tenant instance
func (h *Handler) HandleProxy(w http.ResponseWriter, r *http.Request) {
	// Get claims from context (set by auth middleware)
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get or create tenant instance for this user
	token := generateToken() // Generate a new token if needed
	instance, err := h.tenantClient.GetOrCreateInstance(r.Context(), claims.Subject, token)
	if err != nil {
		log.Printf("Failed to get/create tenant instance for user %s: %v", claims.Subject, err)
		http.Error(w, "Failed to provision instance", http.StatusServiceUnavailable)
		return
	}

	// Parse the tenant endpoint URL
	target, err := url.Parse(instance.Endpoint)
	if err != nil {
		log.Printf("Invalid tenant endpoint %s: %v", instance.Endpoint, err)
		http.Error(w, "Invalid tenant endpoint", http.StatusInternalServerError)
		return
	}

	// Create a reverse proxy for this specific request
	proxy := httputil.NewSingleHostReverseProxy(target)

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
		req.Host = target.Host
	}

	// Proxy the request
	proxy.ServeHTTP(w, r)
}