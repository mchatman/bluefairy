package gateway

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/db"
)

// RegisterRoutes registers the gateway API routes on the given mux.
// All routes require JWT authentication.
func RegisterRoutes(mux *http.ServeMux, provisioner *Provisioner, jwtSecret string) {
	amw := auth.Middleware(jwtSecret)

	inner := http.NewServeMux()
	inner.HandleFunc("GET /api/gateway/connect", handleConnect(provisioner))
	inner.HandleFunc("POST /api/gateway/stop", handleStop(provisioner))
	inner.HandleFunc("POST /api/gateway/restart", handleRestart(provisioner))
	inner.HandleFunc("GET /api/gateway/status", handleStatus(provisioner))

	// Wrap with auth middleware and register under a prefix pattern that
	// matches all /api/gateway/* paths.
	mux.Handle("/api/gateway/", amw(inner))
}

// ---------------------------------------------------------------------------
// GET /api/gateway/connect
// ---------------------------------------------------------------------------

func handleConnect(p *Provisioner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r.Context())
		if claims == nil {
			writeGWError(w, http.StatusUnauthorized, "auth/missing_token", "Authorization required")
			return
		}

		result, err := p.Provision(r.Context(), claims.Subject, claims.Email)
		if err != nil {
			slog.Error("[gateway:connect] provision failed",
				"user", claims.Subject, "error", err)
			writeGWError(w, http.StatusInternalServerError,
				"gateway/provision_failed", "Failed to start gateway instance")
			return
		}

		writeGWJSON(w, http.StatusOK, map[string]interface{}{
			"ok": true,
			"data": map[string]interface{}{
				"port": result.Port,
			},
		})
	}
}

// ---------------------------------------------------------------------------
// POST /api/gateway/stop
// ---------------------------------------------------------------------------

func handleStop(p *Provisioner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r.Context())
		if claims == nil {
			writeGWError(w, http.StatusUnauthorized, "auth/missing_token", "Authorization required")
			return
		}

		if err := p.Stop(r.Context(), claims.Subject); err != nil {
			slog.Error("[gateway:stop] failed",
				"user", claims.Subject, "error", err)
			writeGWError(w, http.StatusInternalServerError,
				"gateway/stop_failed", "Failed to stop gateway")
			return
		}

		writeGWJSON(w, http.StatusOK, map[string]interface{}{
			"ok": true,
			"data": map[string]interface{}{
				"status":  "stopped",
				"message": "Gateway stopped",
			},
		})
	}
}

// ---------------------------------------------------------------------------
// POST /api/gateway/restart
// ---------------------------------------------------------------------------

func handleRestart(p *Provisioner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r.Context())
		if claims == nil {
			writeGWError(w, http.StatusUnauthorized, "auth/missing_token", "Authorization required")
			return
		}

		result, err := p.Restart(r.Context(), claims.Subject, claims.Email)
		if err != nil {
			slog.Error("[gateway:restart] failed",
				"user", claims.Subject, "error", err)
			writeGWError(w, http.StatusInternalServerError,
				"gateway/restart_failed", "Failed to restart gateway")
			return
		}

		writeGWJSON(w, http.StatusOK, map[string]interface{}{
			"ok": true,
			"data": map[string]interface{}{
				"status":  "running",
				"message": "Gateway restarted on port " + itoa(result.Port),
			},
		})
	}
}

// ---------------------------------------------------------------------------
// GET /api/gateway/status
// ---------------------------------------------------------------------------

func handleStatus(p *Provisioner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r.Context())
		if claims == nil {
			writeGWError(w, http.StatusUnauthorized, "auth/missing_token", "Authorization required")
			return
		}

		pool := db.Pool()

		var (
			instID         string
			status         string
			gatewayToken   string
			healthFailures int
			lastHealthyAt  *time.Time
			startedAt      *time.Time
		)
		err := pool.QueryRow(r.Context(),
			`SELECT id, status, gateway_token, health_failures, last_healthy_at, started_at
			 FROM gateway_instances
			 WHERE user_id = $1
			 ORDER BY created_at DESC
			 LIMIT 1`, claims.Subject,
		).Scan(&instID, &status, &gatewayToken, &healthFailures, &lastHealthyAt, &startedAt)

		if err != nil {
			// No instance found — return stopped status.
			writeGWJSON(w, http.StatusOK, map[string]interface{}{
				"ok": true,
				"data": map[string]interface{}{
					"status":         "stopped",
					"healthFailures": 0,
					"lastHealthyAt":  nil,
					"startedAt":      nil,
				},
			})
			return
		}

		// Build the WebSocket endpoint URL for the Mac app.
		// Uses the request's Host header to construct the public-facing URL.
		var endpoint string
		if status == "running" {
			scheme := "wss"
			host := r.Header.Get("X-Forwarded-Host")
			if host == "" {
				host = r.Host
			}
			endpoint = fmt.Sprintf("%s://%s/gw/%s", scheme, host, claims.Subject)
		}

		data := map[string]interface{}{
			"status":         status,
			"healthFailures": healthFailures,
			"lastHealthyAt":  nil,
			"startedAt":      nil,
		}
		if endpoint != "" {
			data["endpoint"] = endpoint
			data["token"] = gatewayToken
		}
		if lastHealthyAt != nil {
			data["lastHealthyAt"] = lastHealthyAt.UTC().Format(time.RFC3339)
		}
		if startedAt != nil {
			data["startedAt"] = startedAt.UTC().Format(time.RFC3339)
		}

		writeGWJSON(w, http.StatusOK, map[string]interface{}{
			"ok":   true,
			"data": data,
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeGWJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeGWError(w http.ResponseWriter, status int, code, message string) {
	writeGWJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
