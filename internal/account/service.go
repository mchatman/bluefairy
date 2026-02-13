package account

import (
	"context"
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) CreateAccount(ctx context.Context, name string) (*Account, error) {
	return s.repo.Create(ctx, name)
}

func (s *Service) GetAccount(ctx context.Context, id string) (*Account, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *Service) UpdateAccount(ctx context.Context, account *Account) error {
	return s.repo.Update(ctx, account)
}