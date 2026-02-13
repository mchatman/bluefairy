package user

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

type User struct {
	ID            string     `json:"id"`
	AccountID     string     `json:"account_id"`
	Email         string     `json:"email"`
	DisplayName   *string    `json:"display_name,omitempty"`
	PasswordHash  string     `json:"-"`
	EmailVerified bool       `json:"email_verified"`
	Role          string     `json:"role"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
}

func (r *Repository) Create(ctx context.Context, accountID, email, passwordHash string, displayName *string, role string) (*User, error) {
	query := `
		INSERT INTO users (account_id, email, password_hash, display_name, role)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, account_id, email, display_name, email_verified, role, created_at, updated_at, deleted_at
	`

	user := &User{}
	err := r.db.QueryRow(ctx, query, accountID, email, passwordHash, displayName, role).Scan(
		&user.ID,
		&user.AccountID,
		&user.Email,
		&user.DisplayName,
		&user.EmailVerified,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)

	return user, err
}

func (r *Repository) GetByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, account_id, email, display_name, password_hash, email_verified, role, created_at, updated_at, deleted_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL
	`

	user := &User{}
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.AccountID,
		&user.Email,
		&user.DisplayName,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}

	return user, err
}

func (r *Repository) GetByID(ctx context.Context, id string) (*User, error) {
	query := `
		SELECT id, account_id, email, display_name, password_hash, email_verified, role, created_at, updated_at, deleted_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`

	user := &User{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.AccountID,
		&user.Email,
		&user.DisplayName,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}

	return user, err
}