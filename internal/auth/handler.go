package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mchatman/bluefairy/internal/account"
	"github.com/mchatman/bluefairy/internal/config"
	"github.com/mchatman/bluefairy/internal/tenant"
	"github.com/mchatman/bluefairy/internal/user"
)

var emailRE = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

const (
	minPasswordLen = 10
	maxPasswordLen = 256
)

// Handler provides HTTP handlers for authentication endpoints including
// signup, login, and token refresh. It coordinates between the user service,
// account service, tenant resolver, and refresh token store.
type Handler struct {
	cfg            *config.Config
	userService    *user.Service
	accountService *account.Service
	tenantClient   tenant.Resolver
	refreshStore   *RefreshStore
}

func NewHandler(cfg *config.Config, userService *user.Service, accountService *account.Service, refreshStore *RefreshStore, tenants tenant.Resolver) *Handler {
	return &Handler{
		cfg:            cfg,
		userService:    userService,
		accountService: accountService,
		tenantClient:   tenants,
		refreshStore:   refreshStore,
	}
}

type SignupRequest struct {
	Email       string  `json:"email"`
	Password    string  `json:"password"`
	DisplayName *string `json:"displayName"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	User         *user.User `json:"user"`
	AccessToken  string     `json:"accessToken"`
	RefreshToken string     `json:"refreshToken,omitempty"`
	ExpiresAt    string     `json:"expiresAt"`
}

// TokenPairResult holds the raw tokens returned by issueTokenPair.
type TokenPairResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// issueTokenPair creates a new access + refresh token pair for the given user,
// stores the refresh token hash, and returns both raw tokens.
func (h *Handler) issueTokenPair(ctx context.Context, usr *user.User) (*TokenPairResult, error) {
	token, err := SignAccessToken(h.cfg.JWTSecret, usr.ID, usr.Email, "free", h.cfg.AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("signing access token: %w", err)
	}

	rawRefresh := GenerateOpaqueToken()
	refreshHash := SHA256Hash(rawRefresh)
	refreshExpiry := time.Now().Add(time.Duration(h.cfg.RefreshTokenTTLDays) * 24 * time.Hour)
	if err := h.refreshStore.Create(ctx, usr.ID, refreshHash, refreshExpiry); err != nil {
		return nil, fmt.Errorf("storing refresh token: %w", err)
	}

	return &TokenPairResult{
		AccessToken:  token.AccessToken,
		RefreshToken: rawRefresh,
		ExpiresAt:    token.ExpiresAt,
	}, nil
}

// RefreshToken validates and rotates a raw refresh token, then issues a new
// access + refresh token pair. Used by both the HandleRefreshToken HTTP endpoint
// and the dashboard's transparent cookie refresh.
func (h *Handler) RefreshToken(ctx context.Context, rawRefresh string) (*user.User, *TokenPairResult, error) {
	oldHash := SHA256Hash(rawRefresh)

	userID, err := h.refreshStore.Validate(ctx, oldHash)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid or expired refresh token")
	}

	// Revoke old token (rotation)
	_ = h.refreshStore.Revoke(ctx, oldHash)

	usr, err := h.userService.GetUser(ctx, userID)
	if err != nil || usr == nil {
		return nil, nil, fmt.Errorf("user not found")
	}

	tokens, err := h.issueTokenPair(ctx, usr)
	if err != nil {
		return nil, nil, err
	}

	return usr, tokens, nil
}

// RevokeAllTokens revokes all refresh tokens for a user (e.g. on logout).
func (h *Handler) RevokeAllTokens(ctx context.Context, userID string) error {
	return h.refreshStore.RevokeAllForUser(ctx, userID)
}

// Signup handles POST /auth/signup. It validates the email and password,
// creates an account and user, provisions a tenant instance, and returns
// JWT access + refresh tokens.
func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || !emailRE.MatchString(req.Email) {
		http.Error(w, "Invalid email", http.StatusBadRequest)
		return
	}

	if len(req.Password) < minPasswordLen || len(req.Password) > maxPasswordLen {
		http.Error(w, "Password must be between 10 and 256 characters", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	accountName := req.Email
	if req.DisplayName != nil && *req.DisplayName != "" {
		accountName = *req.DisplayName
	}

	acc, err := h.accountService.CreateAccount(ctx, accountName)
	if err != nil {
		http.Error(w, "Failed to create account", http.StatusInternalServerError)
		return
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "Failed to process password", http.StatusInternalServerError)
		return
	}

	usr, err := h.userService.CreateUser(ctx, acc.ID, req.Email, passwordHash, req.DisplayName, "owner")
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Provision tenant instance (non-blocking — signup succeeds even if this fails)
	gatewayToken := GenerateOpaqueToken()
	if instance, err := h.tenantClient.CreateInstance(ctx, usr.ID, gatewayToken); err != nil {
		log.Printf("[auth] failed to provision tenant for user %s: %v", usr.ID, err)
	} else {
		log.Printf("[auth] provisioned tenant instance %s for user %s", instance.Name, usr.ID)
	}

	tokens, err := h.issueTokenPair(ctx, usr)
	if err != nil {
		log.Printf("[auth] failed to issue tokens for user %s: %v", usr.ID, err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AuthResponse{
		User:         usr,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt.Format(time.RFC3339),
	})
}

// Login handles POST /auth/login. It verifies the user's credentials
// (supporting both argon2id and legacy bcrypt hashes) and returns
// JWT access + refresh tokens.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	usr, err := h.userService.GetUserByEmail(ctx, req.Email)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if usr == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !VerifyPassword(usr.PasswordHash, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	tokens, err := h.issueTokenPair(ctx, usr)
	if err != nil {
		log.Printf("[auth] failed to issue tokens for user %s: %v", usr.ID, err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		User:         usr,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt.Format(time.RFC3339),
	})
}

const refreshCookieName = "aware_refresh"

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// Refresh handles token rotation: validates the old refresh token, revokes it,
// and issues a new access + refresh token pair.
func (h *Handler) HandleRefreshToken(w http.ResponseWriter, r *http.Request) {
	// Read refresh token from cookie first, then fall back to request body
	var rawRefresh string
	if c, err := r.Cookie(refreshCookieName); err == nil && c.Value != "" {
		rawRefresh = c.Value
	} else {
		var req RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.RefreshToken != "" {
			rawRefresh = req.RefreshToken
		}
	}

	if rawRefresh == "" {
		http.Error(w, "Refresh token required", http.StatusBadRequest)
		return
	}

	usr, tokens, err := h.RefreshToken(r.Context(), rawRefresh)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		User:         usr,
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    tokens.ExpiresAt.Format(time.RFC3339),
	})
}
