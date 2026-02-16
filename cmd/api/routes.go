package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"

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
		}
	})

	return router
}