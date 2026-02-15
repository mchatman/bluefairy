// Package tenant provides client interfaces for looking up tenant instances.
package tenant

import "context"

// Resolver looks up tenant instances by user ID.
type Resolver interface {
	GetInstanceFromOrchestrator(ctx context.Context, userID string) (*Instance, error)
	GetOrCreateInstance(ctx context.Context, userID string, token string) (*Instance, error)
}

// Instance represents a tenant instance.
type Instance struct {
	Name     string // instance name from orchestrator (e.g. "tenant-1c9de7b5")
	Endpoint string // URL to connect to (e.g. "http://24.199.73.199" or "http://tenant-1c9de7b5.internal.wareit.ai")
	Host     string // hostname for Host header routing (e.g. "tenant-1c9de7b5.internal.wareit.ai"); empty = use Endpoint host
	Token    string // gateway token for authentication
}
