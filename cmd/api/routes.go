package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mchatman/bluefairy/internal/account"
	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/proxy"
	"github.com/mchatman/bluefairy/internal/proxy/static"
	"github.com/mchatman/bluefairy/internal/tenant"
	"github.com/mchatman/bluefairy/internal/user"
)



func (a *App) loadRoutes() {
	// Initialize repositories and services needed by both dashboard and API
	accountRepo := account.NewRepository(a.pool)
	userRepo := user.NewRepository(a.pool)
	accountService := account.NewService(accountRepo)
	userService := user.NewService(userRepo)

	// Tenant resolver — always goes through the tenant-provisioner API
	tenants := tenant.NewClient(a.config.TenantProvisionerURL, a.config.TenantBaseURL)

	// Refresh store created once and shared by all auth consumers
	repo := auth.NewRepository(a.pool)

	// Auth handler shared by both API routes and dashboard login
	authHandler := auth.NewHandler(a.config, userService, accountService, repo, tenants)

	// Dashboard proxy — served on dashboard.wareit.ai
	dashboard := proxy.NewDashboardHandler(a.config, authHandler, static.LoginHTML, tenants)

	// API router — served on all other hosts
	apiRouter := a.buildAPIRouter(userService, authHandler, tenants)

	// Top-level mux routes by Host header
	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	// Host-based routing: requests to the dashboard hostname are served by
	// the DashboardHandler (login, auth callbacks, tenant reverse-proxy);
	// everything else hits the JSON API router.
	router.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		host := stripPort(r.Host)

		if host == a.config.DashboardHost {
			dashboard.ServeHTTP(w, r)
		} else {
			apiRouter.ServeHTTP(w, r)
		}
	})

	a.router = router
}

// stripPort removes the port suffix from a host string (e.g. "example.com:8080"
// becomes "example.com"). IPv6 addresses in brackets are handled correctly.
func stripPort(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		// No port present or malformed — return as-is.
		return hostPort
	}
	return host
}

// isWebSocketUpgrade returns true if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	for _, v := range r.Header["Connection"] {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}

func (a *App) buildAPIRouter(userService *user.Service, authHandler *auth.Handler, tenants *tenant.Client) http.Handler {
	router := chi.NewRouter()

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Bluefairy API"))
	})

	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Auth routes (public)
	router.Post("/auth/signup", authHandler.Signup)
	router.Post("/auth/login", authHandler.Login)
	router.Post("/auth/refresh", authHandler.HandleRefreshToken)

	tenantClient := tenants

	// Root-level WebSocket proxy — the tenant app in the workspace iframe
	// connects its WebSocket to wss://<location.host> (no path). We intercept
	// WebSocket upgrades at the root and proxy them to the tenant.
	// Auth is via the "token" cookie set by the /workspace/ handler.
	var rootWSHandler http.HandlerFunc

	// Protected routes (require authentication)
	router.Group(func(r chi.Router) {
		r.Use(auth.Middleware(a.config.JWTSecret))

		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			claims := auth.GetClaims(r.Context())
			if claims == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			usr, err := userService.GetUser(r.Context(), claims.Subject)
			if err != nil {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(usr)
		})

		// Instance lookup — returns the tenant URL for the authenticated user
		r.Get("/instance", func(w http.ResponseWriter, r *http.Request) {
			claims := auth.GetClaims(r.Context())
			if claims == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			inst, err := tenantClient.GetInstance(r.Context(), claims.Subject)
			if err != nil {
				log.Printf("instance lookup failed for user %s: %v", claims.Subject, err)
				http.Error(w, "Failed to look up instance", http.StatusBadGateway)
				return
			}
			if inst == nil {
				http.Error(w, "No instance found", http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"endpoint":      inst.Endpoint,
				"name":          inst.Name,
				"gateway_token": inst.Token,
			})
		})

		// Proxy authenticated requests to tenant instances
		proxyHandler, err := proxy.NewHandler(a.config.ProxySecret, tenants)
		if err != nil {
			// Log error but don't fail startup
		} else {
			r.HandleFunc("/api/*", proxyHandler.HandleProxy)
			r.HandleFunc("/gateway/*", proxyHandler.HandleProxy)
			// Workspace proxy — serves the tenant UI in an iframe from aware-web.
			// Auth is via ?token=JWT query param since the iframe is cross-origin.
			r.HandleFunc("/workspace/*", proxyHandler.HandleWorkspace)

			// Expose the workspace handler for root-level WebSocket upgrades.
			rootWSHandler = func(w http.ResponseWriter, r *http.Request) {
				proxyHandler.HandleWorkspace(w, r)
			}
		}
	})

	// Override the root GET handler to also handle WebSocket upgrades.
	// The tenant app connects to wss://<host>/ with no path prefix.
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if isWebSocketUpgrade(r) && rootWSHandler != nil {
			// Run auth middleware manually for the WebSocket request.
			auth.Middleware(a.config.JWTSecret)(http.HandlerFunc(rootWSHandler)).ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Bluefairy API"))
	})

	return router
}