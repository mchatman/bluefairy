// Package user provides persistence and business logic for user accounts,
// including CRUD operations and password verification.
package user

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository handles user persistence in PostgreSQL.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository creates a new user Repository backed by the given connection pool.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// User represents a user record in the database.
type User struct {
	ID            string     `json:"id"`                    // UUID primary key.
	AccountID     string     `json:"account_id"`            // Foreign key to the owning account.
	Email         string     `json:"email"`                 // Unique email address.
	DisplayName   *string    `json:"display_name,omitempty"` // Optional display name.
	PasswordHash  string     `json:"-"`                     // Argon2id or bcrypt hash (never serialized to JSON).
	EmailVerified bool       `json:"email_verified"`        // Whether the email has been confirmed.
	Role          string     `json:"role"`                  // Role within the account (e.g. "owner", "member").
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"` // Soft-delete timestamp.
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