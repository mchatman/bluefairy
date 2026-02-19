package oauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mchatman/bluefairy/internal/auth"
)

// Handler serves OAuth connect/callback/status/token/disconnect routes.
type Handler struct {
	repo      *Repository
	providers map[string]Provider
	jwtSecret string
}

// NewHandler creates an OAuth handler with the given providers registered.
func NewHandler(repo *Repository, jwtSecret string, providers ...Provider) *Handler {
	pm := make(map[string]Provider, len(providers))
	for _, p := range providers {
		pm[p.Name()] = p
	}
	return &Handler{repo: repo, providers: pm, jwtSecret: jwtSecret}
}

// Mount registers all OAuth routes onto a chi router under /oauth/{provider}.
//
//	GET  /oauth/{provider}           — redirect to consent screen
//	GET  /oauth/{provider}/callback  — handle Google/provider redirect
//	GET  /oauth/{provider}/status    — is this provider connected? (auth required)
//	GET  /oauth/{provider}/token     — get a fresh access token (auth required)
//	DELETE /oauth/{provider}         — disconnect (auth required)
//	GET  /oauth                      — list all connected providers (auth required)
func (h *Handler) Mount(r chi.Router) {
	r.Get("/oauth", auth.MiddlewareFunc(h.jwtSecret, h.List))

	r.Route("/oauth/{provider}", func(r chi.Router) {
		r.Get("/", h.Connect)
		r.Get("/callback", h.Callback)
		r.Get("/status", auth.MiddlewareFunc(h.jwtSecret, h.Status))
		r.Get("/token", auth.MiddlewareFunc(h.jwtSecret, h.Token))
		r.Delete("/", auth.MiddlewareFunc(h.jwtSecret, h.Disconnect))
	})
}

// Connect redirects the user to the provider's consent screen.
// Accepts the user's JWT via Authorization header or ?token= query param.
func (h *Handler) Connect(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	p, ok := h.providers[providerName]
	if !ok {
		http.Error(w, fmt.Sprintf("unknown provider: %s", providerName), http.StatusBadRequest)
		return
	}

	// Accept token from header or query param (browser redirect needs query param).
	tokenStr := bearerToken(r)
	if tokenStr == "" {
		tokenStr = r.URL.Query().Get("token")
	}
	if tokenStr == "" {
		http.Error(w, "missing token — pass as Authorization header or ?token=", http.StatusUnauthorized)
		return
	}

	claims, err := auth.VerifyAccessToken(h.jwtSecret, tokenStr)
	if err != nil {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Encode user ID in state so Callback knows who to link.
	state, err := auth.SignAccessToken(h.jwtSecret, claims.Subject, claims.Email, claims.Tier, 15*time.Minute)
	if err != nil {
		http.Error(w, "failed to build state", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, p.BuildAuthURL(state.AccessToken), http.StatusFound)
}

// Callback handles the provider redirect after the user grants consent.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	p, ok := h.providers[providerName]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(closePage("Unknown provider", providerName)))
		return
	}

	if oauthErr := r.URL.Query().Get("error"); oauthErr != "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(closePage("Authorization denied", oauthErr)))
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(closePage("Missing parameters", "Invalid callback")))
		return
	}

	// Verify state to recover user ID.
	claims, err := auth.VerifyAccessToken(h.jwtSecret, state)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(closePage("Invalid state", "Please try connecting again.")))
		return
	}
	userID := claims.Subject

	tok, err := p.ExchangeCode(code)
	if err != nil {
		log.Printf("[oauth/%s/callback] code exchange failed: %v", providerName, err)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(closePage("Connection failed", "Token exchange failed. Please try again.")))
		return
	}

	if tok.RefreshToken == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(closePage("Missing refresh token", "Please revoke access and try again.")))
		return
	}

	email, err := p.GetEmail(tok.AccessToken)
	if err != nil {
		log.Printf("[oauth/%s/callback] get email failed: %v", providerName, err)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(closePage("Connection failed", "Could not fetch account email.")))
		return
	}

	expiresAt := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	if err := h.repo.Upsert(r.Context(), userID, providerName, email, tok.AccessToken, tok.RefreshToken, tok.Scope, expiresAt); err != nil {
		log.Printf("[oauth/%s/callback] upsert failed: %v", providerName, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(closePage("Connection failed", "Could not save connection.")))
		return
	}

	log.Printf("[oauth/%s/callback] connected %s for user %s", providerName, email, userID)
	w.Write([]byte(closePage(fmt.Sprintf("%s connected!", providerName), fmt.Sprintf("Signed in as %s. You can close this window.", email))))
}

// Status returns whether the provider is connected for the authenticated user.
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	userID := auth.GetClaims(r.Context()).Subject

	conn, err := h.repo.Get(r.Context(), userID, providerName)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if conn == nil {
		json.NewEncoder(w).Encode(map[string]any{"connected": false})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"connected":   true,
		"email":       conn.Email,
		"scopes":      conn.Scopes,
		"connectedAt": conn.CreatedAt,
	})
}

// Token returns a valid access token for the provider, refreshing if needed.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	p, ok := h.providers[providerName]
	if !ok {
		http.Error(w, fmt.Sprintf("unknown provider: %s", providerName), http.StatusBadRequest)
		return
	}

	userID := auth.GetClaims(r.Context()).Subject
	conn, err := h.repo.Get(r.Context(), userID, providerName)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if conn == nil {
		http.Error(w, fmt.Sprintf("%s not connected", providerName), http.StatusNotFound)
		return
	}

	// Refresh if expiring within 5 minutes.
	if time.Until(conn.ExpiresAt) < 5*time.Minute {
		refreshed, err := p.RefreshAccessToken(conn.RefreshToken)
		if err != nil {
			log.Printf("[oauth/%s/token] refresh failed for user %s: %v", providerName, userID, err)
			http.Error(w, "failed to refresh token", http.StatusBadGateway)
			return
		}
		expiresAt := time.Now().Add(time.Duration(refreshed.ExpiresIn) * time.Second)
		_ = h.repo.UpdateAccessToken(r.Context(), userID, providerName, refreshed.AccessToken, expiresAt)
		conn.AccessToken = refreshed.AccessToken
		conn.ExpiresAt = expiresAt
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"accessToken": conn.AccessToken,
		"email":       conn.Email,
		"expiresAt":   conn.ExpiresAt,
	})
}

// Disconnect removes the provider connection for the authenticated user.
func (h *Handler) Disconnect(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	userID := auth.GetClaims(r.Context()).Subject

	if err := h.repo.Delete(r.Context(), userID, providerName); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"disconnected": true})
}

// List returns all connected providers for the authenticated user.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetClaims(r.Context()).Subject

	conns, err := h.repo.List(r.Context(), userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	type item struct {
		Provider    string    `json:"provider"`
		Email       string    `json:"email"`
		ConnectedAt time.Time `json:"connectedAt"`
	}
	result := make([]item, 0, len(conns))
	for _, c := range conns {
		result = append(result, item{
			Provider:    c.Provider,
			Email:       c.Email,
			ConnectedAt: c.CreatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && h[:7] == "Bearer " {
		return h[7:]
	}
	return ""
}

func closePage(title, message string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>%s</title>
  <style>
    body { font-family: -apple-system, system-ui, sans-serif; background: #111; color: #fff;
           display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { text-align: center; max-width: 400px; padding: 40px; }
    h1 { font-size: 24px; margin-bottom: 12px; }
    p { color: #888; font-size: 14px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>%s</h1>
    <p>%s</p>
  </div>
</body>
</html>`, title, title, message)
}
