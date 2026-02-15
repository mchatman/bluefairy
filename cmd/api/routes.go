package main

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mchatman/bluefairy/internal/account"
	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/proxy"
	"github.com/mchatman/bluefairy/internal/tenant"
	"github.com/mchatman/bluefairy/internal/user"
)

func (a *App) loadRoutes() {
	router := chi.NewRouter()

	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Bluefairy API"))
	})

	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Initialize repositories
	accountRepo := account.NewRepository(a.pool)
	userRepo := user.NewRepository(a.pool)

	// Initialize services
	accountService := account.NewService(accountRepo)
	userService := user.NewService(userRepo)

	// Initialize handlers
	authHandler := auth.NewHandler(a.config, userService, accountService)

	// Auth routes
	router.Post("/auth/signup", authHandler.Signup)
	router.Post("/auth/login", authHandler.Login)

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
		proxyHandler, err := proxy.NewHandler("")
		if err != nil {
			// Log error but don't fail startup
		} else {
			r.HandleFunc("/api/*", proxyHandler.HandleProxy)
			r.HandleFunc("/gateway/*", proxyHandler.HandleProxy)
		}
	})

	a.router = router
}