package proxy

// Constants for cookie names used by the proxy layer.
const (
	// DashboardCookieName is the HTTP cookie name for the dashboard JWT access token.
	DashboardCookieName = "aware_dashboard"

	// RefreshCookieName is the HTTP cookie name for the opaque refresh token.
	RefreshCookieName = "aware_refresh"
)
