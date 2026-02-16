package user

import (
	"context"
	"errors"
)

// Service provides user management operations backed by a PostgreSQL repository.
type Service struct {
	repo *Repository
}

// NewService creates a new user Service with the given repository.
func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// CreateUser creates a new user with the given pre-hashed password.
// The caller is responsible for hashing the password (e.g. via auth.HashPassword).
// Returns an error if a user with the same email already exists.
func (s *Service) CreateUser(ctx context.Context, accountID, email, passwordHash string, displayName *string, role string) (*User, error) {
	// Check if user already exists
	existing, err := s.repo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, errors.New("user already exists")
	}

	// Create user
	return s.repo.Create(ctx, accountID, email, passwordHash, displayName, role)
}

// GetUser retrieves a user by their unique ID.
// Returns nil if the user does not exist or has been soft-deleted.
func (s *Service) GetUser(ctx context.Context, id string) (*User, error) {
	return s.repo.GetByID(ctx, id)
}

// GetUserByEmail retrieves a user by their email address.
// Returns nil if no active user with that email exists.
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.repo.GetByEmail(ctx, email)
}
