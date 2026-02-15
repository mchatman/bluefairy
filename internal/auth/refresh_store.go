package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RefreshStore manages refresh token persistence in PostgreSQL.
type RefreshStore struct {
	db *pgxpool.Pool
}

// NewRefreshStore creates a new RefreshStore backed by the given connection pool.
func NewRefreshStore(db *pgxpool.Pool) *RefreshStore {
	return &RefreshStore{db: db}
}

// Create inserts a new refresh token record.
func (s *RefreshStore) Create(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`
	_, err := s.db.Exec(ctx, query, userID, tokenHash, expiresAt)
	return err
}

// Validate looks up a non-revoked, non-expired refresh token by its hash.
// Returns the associated user_id if valid.
func (s *RefreshStore) Validate(ctx context.Context, tokenHash string) (string, error) {
	query := `
		SELECT user_id FROM refresh_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
	`
	var userID string
	err := s.db.QueryRow(ctx, query, tokenHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errors.New("invalid or expired refresh token")
	}
	if err != nil {
		return "", err
	}
	return userID, nil
}

// Revoke marks a single refresh token as revoked.
func (s *RefreshStore) Revoke(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE token_hash = $1 AND revoked_at IS NULL
	`
	_, err := s.db.Exec(ctx, query, tokenHash)
	return err
}

// RevokeAllForUser revokes every refresh token belonging to the given user.
func (s *RefreshStore) RevokeAllForUser(ctx context.Context, userID string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL
	`
	_, err := s.db.Exec(ctx, query, userID)
	return err
}
