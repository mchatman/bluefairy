package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the Go server.
// Values are read from environment variables at startup.
type Config struct {
	// Database
	DatabaseURL string

	// Auth
	JWTSecret           string
	AccessTokenTTL      time.Duration
	RefreshTokenTTLDays int

	// Server
	Port int

	// Gateway
	StateRoot      string
	GatewayImage   string
	GatewayRuntime string // "docker" or "fly"

	// Fly (optional, required when GatewayRuntime == "fly")
	FlyAPIToken      string
	FlyGatewayApp    string
	FlyGatewayRegion string
	FlyGatewayImage  string
	FlyIdleTimeout   time.Duration

	// External
	AnthropicOAuthToken string
	AnthropicAPIKey     string

	// Health
	HealthCheckInterval time.Duration
	MaxHealthFailures   int

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

	// Server
	port := optionalInt("PORT", 8000)

	// Auth
	accessTTLMin := optionalInt("JWT_ACCESS_TTL_MIN", 15)
	refreshTTLDays := optionalInt("JWT_REFRESH_TTL_DAYS", 30)

	// Gateway
	stateRoot := optional("STATE_ROOT", "/tmp/aware-data")
	gatewayImage := optional("GATEWAY_IMAGE", "aware-gateway:local")
	gatewayRuntime := optional("GATEWAY_RUNTIME", "docker")

	// Fly
	flyAPIToken := optional("FLY_API_TOKEN", "")
	flyGatewayApp := optional("FLY_GATEWAY_APP", "")
	flyGatewayRegion := optional("FLY_GATEWAY_REGION", "")
	flyGatewayImage := optional("FLY_GATEWAY_IMAGE", "")
	flyIdleTimeoutSec := optionalInt("FLY_IDLE_TIMEOUT_SEC", 300)

	// External
	anthropicOAuthToken := optional("ANTHROPIC_OAUTH_TOKEN", "")
	anthropicAPIKey := optional("ANTHROPIC_API_KEY", "")

	// Health
	healthCheckSec := optionalInt("HEALTH_CHECK_INTERVAL_SEC", 30)
	maxHealthFailures := optionalInt("MAX_HEALTH_FAILURES", 3)

	// Misc
	nodeEnv := optional("NODE_ENV", "production")

	// Validate gateway runtime
	if gatewayRuntime != "docker" && gatewayRuntime != "fly" {
		errs = append(errs, fmt.Sprintf("GATEWAY_RUNTIME must be \"docker\" or \"fly\", got %q", gatewayRuntime))
	}

	// When running on Fly, require Fly-specific vars
	if gatewayRuntime == "fly" {
		if flyAPIToken == "" {
			errs = append(errs, "FLY_API_TOKEN is required when GATEWAY_RUNTIME=fly")
		}
		if flyGatewayApp == "" {
			errs = append(errs, "FLY_GATEWAY_APP is required when GATEWAY_RUNTIME=fly")
		}
		if flyGatewayRegion == "" {
			errs = append(errs, "FLY_GATEWAY_REGION is required when GATEWAY_RUNTIME=fly")
		}
		if flyGatewayImage == "" {
			errs = append(errs, "FLY_GATEWAY_IMAGE is required when GATEWAY_RUNTIME=fly")
		}
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("config validation failed:\n  %s", joinErrors(errs))
	}

	return &Config{
		DatabaseURL:         databaseURL,
		JWTSecret:           jwtSecret,
		AccessTokenTTL:      time.Duration(accessTTLMin) * time.Minute,
		RefreshTokenTTLDays: refreshTTLDays,
		Port:                port,
		StateRoot:           stateRoot,
		GatewayImage:        gatewayImage,
		GatewayRuntime:      gatewayRuntime,
		FlyAPIToken:         flyAPIToken,
		FlyGatewayApp:       flyGatewayApp,
		FlyGatewayRegion:    flyGatewayRegion,
		FlyGatewayImage:     flyGatewayImage,
		FlyIdleTimeout:      time.Duration(flyIdleTimeoutSec) * time.Second,
		AnthropicOAuthToken: anthropicOAuthToken,
		AnthropicAPIKey:     anthropicAPIKey,
		HealthCheckInterval: time.Duration(healthCheckSec) * time.Second,
		MaxHealthFailures:   maxHealthFailures,
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
