package oauth

// TokenResponse is the standard response from an OAuth token endpoint.
type TokenResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	Scope        string
}

// Provider defines the interface each OAuth provider must implement.
type Provider interface {
	// Name returns the provider identifier stored in the DB (e.g. "google").
	Name() string
	// BuildAuthURL returns the consent screen URL with the given state.
	BuildAuthURL(state string) string
	// ExchangeCode exchanges an authorization code for tokens.
	ExchangeCode(code string) (*TokenResponse, error)
	// RefreshAccessToken uses a refresh token to get a new access token.
	RefreshAccessToken(refreshToken string) (*TokenResponse, error)
	// GetEmail fetches the user's email address using the access token.
	GetEmail(accessToken string) (string, error)
}
