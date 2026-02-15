// Package tenant provides client interfaces for looking up tenant instances.
package tenant

import "context"

// Resolver looks up tenant instances by user ID.
type Resolver interface {
	GetInstanceFromOrchestrator(ctx context.Context, userID string) (*Instance, error)
	GetOrCreateInstance(ctx context.Context, userID string, token string) (*Instance, error)
}
