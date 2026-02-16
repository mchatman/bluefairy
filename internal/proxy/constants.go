package proxy

// Constants for cookie names and well-known hostnames used by the proxy layer.
const (
	// DashboardCookieName is the HTTP cookie name for the dashboard JWT access token.
	DashboardCookieName = "aware_dashboard"

	// RefreshCookieName is the HTTP cookie name for the opaque refresh token.
	RefreshCookieName = "aware_refresh"

	// DashboardHost is the hostname that triggers dashboard-mode routing.
	DashboardHost = "dashboard.wareit.ai"
)
