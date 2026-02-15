package main

import (
	"encoding/json"
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

const dashboardHost = "dashboard.wareit.ai"

func (a *App) loadRoutes() {
	// Initialize repositories and services needed by both dashboard and API
	accountRepo := account.NewRepository(a.pool)
	userRepo := user.NewRepository(a.pool)
	accountService := account.NewService(accountRepo)
	userService := user.NewService(userRepo)

	// Auth handler shared by both API routes and dashboard login
	authHandler := auth.NewHandler(a.config, userService, accountService, a.pool)

	// Dashboard proxy — served on dashboard.wareit.ai
	dashboard := proxy.NewDashboardHandler(a.config, a.pool, userService, authHandler, static.LoginHTML)

	// API router — served on all other hosts
	apiRouter := a.buildAPIRouter(userService, authHandler)

	// Top-level mux routes by Host header
	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	router.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		// Strip port if present
		if i := len(host) - 1; i > 0 {
			for i > 0 && host[i] != ':' && host[i] != ']' {
				i--
			}
			if i > 0 && host[i] == ':' {
				host = host[:i]
			}
		}

		if host == dashboardHost {
			dashboard.ServeHTTP(w, r)
		} else {
			apiRouter.ServeHTTP(w, r)
		}
	})

	a.router = router
}

func (a *App) buildAPIRouter(userService *user.Service, authHandler *auth.Handler) http.Handler {
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
	router.Post("/auth/refresh", authHandler.Refresh)

	// Initialize tenant client for instance lookups
	tenantClient := tenant.NewClient()

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

			inst, err := tenantClient.GetInstanceFromOrchestrator(r.Context(), claims.Subject)
			if err != nil {
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
		proxyHandler, err := proxy.NewHandler("", a.config.ProxySecret)
		if err != nil {
			// Log error but don't fail startup
		} else {
			r.HandleFunc("/api/*", proxyHandler.HandleProxy)
			r.HandleFunc("/gateway/*", proxyHandler.HandleProxy)
		}
	})

	return router
}