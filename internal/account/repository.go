package account

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

type Account struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	StripeCustomerID     *string    `json:"stripe_customer_id,omitempty"`
	StripeSubscriptionID *string    `json:"stripe_subscription_id,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	DeletedAt            *time.Time `json:"deleted_at,omitempty"`
}

func (r *Repository) Create(ctx context.Context, name string) (*Account, error) {
	query := `
		INSERT INTO accounts (name)
		VALUES ($1)
		RETURNING id, name, stripe_customer_id, stripe_subscription_id, created_at, updated_at, deleted_at
	`

	account := &Account{}
	err := r.db.QueryRow(ctx, query, name).Scan(
		&account.ID,
		&account.Name,
		&account.StripeCustomerID,
		&account.StripeSubscriptionID,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.DeletedAt,
	)

	return account, err
}

func (r *Repository) GetByID(ctx context.Context, id string) (*Account, error) {
	query := `
		SELECT id, name, stripe_customer_id, stripe_subscription_id, created_at, updated_at, deleted_at
		FROM accounts
		WHERE id = $1 AND deleted_at IS NULL
	`

	account := &Account{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&account.ID,
		&account.Name,
		&account.StripeCustomerID,
		&account.StripeSubscriptionID,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.DeletedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}

	return account, err
}

func (r *Repository) Update(ctx context.Context, account *Account) error {
	query := `
		UPDATE accounts
		SET name = $2, stripe_customer_id = $3, stripe_subscription_id = $4, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`

	_, err := r.db.Exec(ctx, query, account.ID, account.Name, account.StripeCustomerID, account.StripeSubscriptionID)
	return err
}