// Package config loads and validates application configuration from
// environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the Go server.
// Values are read from environment variables at startup via [Load].
type Config struct {
	// DatabaseURL is the PostgreSQL connection string (env: DATABASE_URL, required).
	DatabaseURL string

	// JWTSecret is the HMAC secret used to sign and verify access tokens (env: JWT_SECRET, required).
	JWTSecret string
	// AccessTokenTTL controls how long access tokens are valid (env: JWT_ACCESS_TTL_MIN, default: 15m).
	AccessTokenTTL time.Duration
	// RefreshTokenTTLDays controls refresh token lifetime in days (env: JWT_REFRESH_TTL_DAYS, default: 30).
	RefreshTokenTTLDays int

	// Port is the HTTP listen port (env: PORT, default: 8000).
	Port int

	// TenantProvisionerURL is the base URL of the tenant-provisioner API
	// (env: TENANT_PROVISIONER_URL, required).
	TenantProvisionerURL string

	// TenantBaseURL is the URL template for connecting to tenant instances.
	// The literal "{name}" is replaced with the instance name.
	// Example: "http://{name}.wareit.ai" (env: TENANT_BASE_URL, required).
	TenantBaseURL string

	// DashboardHost is the hostname that triggers dashboard-mode routing
	// (env: DASHBOARD_HOST, default: dashboard.wareit.ai).
	DashboardHost string

	// ProxySecret is the shared secret sent as X-Proxy-Secret to tenant instances
	// for request verification (env: PROXY_SECRET, optional).
	ProxySecret string

	// AnthropicOAuthToken and AnthropicAPIKey are passed through to tenant
	// gateway containers as environment variables.
	AnthropicOAuthToken string // env: ANTHROPIC_OAUTH_TOKEN
	AnthropicAPIKey     string // env: ANTHROPIC_API_KEY

	// NodeEnv is the runtime environment label (env: NODE_ENV, default: "production").
	NodeEnv string
}

// Load reads configuration from environment variables and returns a validated Config.
// Returns an error if any required variable is missing or a value cannot be parsed.
func Load() (*Config, error) {
	var errs []string

	required := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			errs = append(errs, fmt.Sprintf("required env var %s is not set", key))
		}
		return v
	}

	optional := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return fallback
	}

	optionalInt := func(key string, fallback int) int {
		v := os.Getenv(key)
		if v == "" {
			return fallback
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Sprintf("env var %s: expected integer, got %q", key, v))
			return fallback
		}
		return n
	}

	// Required
	databaseURL := required("DATABASE_URL")
	jwtSecret := required("JWT_SECRET")
	tenantProvisionerURL := required("TENANT_PROVISIONER_URL")
	tenantBaseURL := required("TENANT_BASE_URL")

	// Server
	port := optionalInt("PORT", 8000)

	// Auth
	accessTTLMin := optionalInt("JWT_ACCESS_TTL_MIN", 15)
	refreshTTLDays := optionalInt("JWT_REFRESH_TTL_DAYS", 30)

	// Dashboard
	dashboardHost := optional("DASHBOARD_HOST", "dashboard.wareit.ai")

	// Proxy
	proxySecret := optional("PROXY_SECRET", "")

	// External
	anthropicOAuthToken := optional("ANTHROPIC_OAUTH_TOKEN", "")
	anthropicAPIKey := optional("ANTHROPIC_API_KEY", "")

	// Misc
	nodeEnv := optional("NODE_ENV", "production")

	if len(errs) > 0 {
		return nil, fmt.Errorf("config validation failed:\n  %s", joinErrors(errs))
	}

	return &Config{
		DatabaseURL:           databaseURL,
		JWTSecret:             jwtSecret,
		TenantProvisionerURL: tenantProvisionerURL,
		TenantBaseURL:         tenantBaseURL,
		AccessTokenTTL:      time.Duration(accessTTLMin) * time.Minute,
		RefreshTokenTTLDays: refreshTTLDays,
		Port:                port,
		DashboardHost:       dashboardHost,
		ProxySecret:         proxySecret,
		AnthropicOAuthToken: anthropicOAuthToken,
		AnthropicAPIKey:     anthropicAPIKey,
		NodeEnv:             nodeEnv,
	}, nil
}

func joinErrors(errs []string) string {
	result := errs[0]
	for _, e := range errs[1:] {
		result += "\n  " + e
	}
	return result
}
