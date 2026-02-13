package main

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mchatman/bluefairy/internal/account"
	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/proxy"
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

	// Protected routes (require authentication)
	router.Group(func(r chi.Router) {
		r.Use(auth.Middleware(a.config.JWTSecret))

		// Add protected routes here
		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			// Get claims from context (set by auth middleware)
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

			// Return user info
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(usr)
		})

		// Proxy authenticated requests to tenant instances
		proxyHandler, err := proxy.NewHandler("")
		if err != nil {
			// Log error but don't fail startup
			// The proxy handler will create the tenant client internally
		} else {
			// Proxy both /api/* and /gateway/* paths to tenant instances
			r.HandleFunc("/api/*", proxyHandler.HandleProxy)
			r.HandleFunc("/gateway/*", proxyHandler.HandleProxy)
		}
	})

	a.router = router
}