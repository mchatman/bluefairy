package account

import (
	"context"
)

// Service provides business logic for account management.
type Service struct {
	repo *Repository
}

// NewService creates a new account Service with the given repository.
func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// CreateAccount creates a new account with the given display name.
func (s *Service) CreateAccount(ctx context.Context, name string) (*Account, error) {
	return s.repo.Create(ctx, name)
}

// GetAccount retrieves an account by its unique ID.
func (s *Service) GetAccount(ctx context.Context, id string) (*Account, error) {
	return s.repo.GetByID(ctx, id)
}

// UpdateAccount persists changes to an existing account.
func (s *Service) UpdateAccount(ctx context.Context, account *Account) error {
	return s.repo.Update(ctx, account)
}
