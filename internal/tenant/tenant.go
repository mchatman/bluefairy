// Package tenant provides a client for looking up and provisioning per-user
// tenant instances via the tenant-orchestrator HTTP API.
package tenant

import "context"

// Resolver abstracts the lookup and creation of tenant instances.
// Implementations must be safe for concurrent use.
type Resolver interface {
	// GetInstance returns the running instance for the given user,
	// or (nil, nil) if no instance exists.
	GetInstance(ctx context.Context, userID string) (*Instance, error)

	// CreateInstance provisions a new instance for the user with the
	// supplied gateway token. It calls GetInstance first and returns
	// the existing instance if one is already running.
	CreateInstance(ctx context.Context, userID string, token string) (*Instance, error)
}

// Instance represents a running tenant workspace.
type Instance struct {
	// Name is the instance identifier returned by the orchestrator (e.g. "tenant-1c9de7b5").
	Name string

	// Endpoint is the URL used to connect to the tenant
	// (e.g. "http://tenant-1c9de7b5.wareit.ai").
	Endpoint string

	// Token is the gateway authentication token passed to the tenant instance
	// as a query parameter or header.
	Token string
}
