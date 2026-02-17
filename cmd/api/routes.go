package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mchatman/bluefairy/internal/account"
	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/proxy"
	"github.com/mchatman/bluefairy/internal/tenant"
	"github.com/mchatman/bluefairy/internal/user"
)

func (a *App) loadRoutes() {
	// Initialize repositories and services
	accountRepo := account.NewRepository(a.pool)
	userRepo := user.NewRepository(a.pool)
	accountService := account.NewService(accountRepo)
	userService := user.NewService(userRepo)

	tenants := tenant.NewClient(a.config.TenantProvisionerURL, a.config.TenantBaseURL)
	repo := auth.NewRepository(a.pool)
	authHandler := auth.NewHandler(a.config, userService, accountService, repo, tenants)

	// API router — served on api.wareit.ai
	apiRouter := a.buildAPIRouter(userService, authHandler, tenants)

	// Dashboard handler — served on dashboard.wareit.ai.
	// Proxies UI routes to aware-web on Vercel, workspace/WebSocket to tenant.
	dashboardHandler := proxy.NewAppHandler(a.config, authHandler, tenants, a.config.FrontendURL)

	// Top-level mux routes by Host header
	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	router.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		host := stripPort(r.Host)

		if host == a.config.DashboardHost {
			dashboardHandler.ServeHTTP(w, r)
		} else {
			apiRouter.ServeHTTP(w, r)
		}
	})

	a.router = router
}

func stripPort(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
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

		r.Get("/instance", func(w http.ResponseWriter, r *http.Request) {
			claims := auth.GetClaims(r.Context())
			if claims == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			inst, err := tenants.GetInstance(r.Context(), claims.Subject)
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
	})

	// Gateway WebSocket proxy — allows the openclaw Mac app to connect to its
	// tenant gateway using only a gateway token, without a user JWT session.
	//
	// Usage: wss://api.wareit.ai/gateway/ws?tenant=<tenant-name>
	// Auth:  Authorization: Bearer <gateway_token>   (or ?token=<gateway_token>)
	//
	// The token is injected as ?token= on the upstream WebSocket URL so the
	// openclaw gateway can verify it in its connect-frame handler.
	router.Get("/gateway/ws", func(w http.ResponseWriter, r *http.Request) {
		tenantName := r.URL.Query().Get("tenant")
		if tenantName == "" {
			http.Error(w, "tenant query param required", http.StatusBadRequest)
			return
		}

		// Accept token from Authorization header or query param.
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		// Build target URL from the TenantBaseURL template.
		endpoint := strings.ReplaceAll(a.config.TenantBaseURL, "{name}", tenantName)
		target, err := url.Parse(endpoint)
		if err != nil {
			log.Printf("[gateway-ws] invalid tenant URL %q: %v", endpoint, err)
			http.Error(w, "Invalid tenant", http.StatusBadRequest)
			return
		}

		log.Printf("[gateway-ws] proxying tenant=%s target=%s", tenantName, target)
		proxy.ProxyWebSocket(w, r, target, target.Host, token, "", "", a.config.ProxySecret)
	})

	return router
}
