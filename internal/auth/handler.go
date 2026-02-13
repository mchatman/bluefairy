package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

type Handler struct {
	cfg            *config.Config
	userService    *user.Service
	accountService *account.Service
	tenantClient   *tenant.Client
}

func NewHandler(cfg *config.Config, userService *user.Service, accountService *account.Service) *Handler {
	return &Handler{
		cfg:            cfg,
		userService:    userService,
		accountService: accountService,
		tenantClient:   tenant.NewClient(),
	}
}

// generateToken creates a secure random token
func generateToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "fallback-token-signup"
	}
	return hex.EncodeToString(bytes)
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
	User        *user.User `json:"user"`
	AccessToken string     `json:"accessToken"`
	ExpiresAt   string     `json:"expiresAt"`
}

func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate email
	if req.Email == "" || !emailRE.MatchString(req.Email) {
		http.Error(w, "Invalid email", http.StatusBadRequest)
		return
	}

	// Validate password
	if len(req.Password) < minPasswordLen || len(req.Password) > maxPasswordLen {
		http.Error(w, "Password must be between 10 and 256 characters", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Create account (use email or display name as account name)
	accountName := req.Email
	if req.DisplayName != nil && *req.DisplayName != "" {
		accountName = *req.DisplayName
	}

	acc, err := h.accountService.CreateAccount(ctx, accountName)
	if err != nil {
		http.Error(w, "Failed to create account", http.StatusInternalServerError)
		return
	}

	// Create user as owner
	usr, err := h.userService.CreateUser(ctx, acc.ID, req.Email, req.Password, req.DisplayName, "owner")
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Provision tenant instance for the new user
	gatewayToken := generateToken()
	instance, err := h.tenantClient.GetOrCreateInstance(ctx, usr.ID, gatewayToken)
	if err != nil {
		// Log but don't fail signup - instance can be created on first use
		log.Printf("Failed to provision tenant for user %s: %v", usr.ID, err)
	} else {
		log.Printf("Provisioned tenant instance %s for user %s", instance.Name, usr.ID)

		// Optionally update account with tenant instance ID
		// This would require updating the account service to support this
	}

	// Generate JWT token
	token, err := SignAccessToken(h.cfg.JWTSecret, usr.ID, usr.Email, "free", h.cfg.AccessTokenTTL)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Return response
	resp := AuthResponse{
		User:        usr,
		AccessToken: token.AccessToken,
		ExpiresAt:   token.ExpiresAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

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

	// Get user
	usr, err := h.userService.GetUserByEmail(ctx, req.Email)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if usr == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify password
	if !h.userService.VerifyPassword(usr, req.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token, err := SignAccessToken(h.cfg.JWTSecret, usr.ID, usr.Email, "free", h.cfg.AccessTokenTTL)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Return response
	resp := AuthResponse{
		User:        usr,
		AccessToken: token.AccessToken,
		ExpiresAt:   token.ExpiresAt.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}