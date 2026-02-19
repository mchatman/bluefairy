// Package oauth provides a provider-agnostic OAuth connection store and
// per-provider implementations (Google, Microsoft, Slack, etc.).
package oauth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Connection represents a stored OAuth connection for a user + provider pair.
type Connection struct {
	ID           string
	UserID       string
	Provider     string
	Email        string
	AccessToken  string
	RefreshToken string
	Scopes       string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Repository handles persistence for oauth_connections.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository creates a new OAuth connection repository.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// Upsert inserts or updates the OAuth connection for a user + provider.
func (r *Repository) Upsert(ctx context.Context, userID, provider, email, accessToken, refreshToken, scopes string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_connections
		    (user_id, provider, email, access_token, refresh_token, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (user_id, provider) DO UPDATE SET
		    email         = EXCLUDED.email,
		    access_token  = EXCLUDED.access_token,
		    refresh_token = EXCLUDED.refresh_token,
		    scopes        = EXCLUDED.scopes,
		    expires_at    = EXCLUDED.expires_at,
		    updated_at    = NOW()
	`, userID, provider, email, accessToken, refreshToken, scopes, expiresAt)
	return err
}

// UpdateAccessToken replaces just the access token + expiry after a refresh.
func (r *Repository) UpdateAccessToken(ctx context.Context, userID, provider, accessToken string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE oauth_connections
		SET access_token = $3, expires_at = $4, updated_at = NOW()
		WHERE user_id = $1 AND provider = $2
	`, userID, provider, accessToken, expiresAt)
	return err
}

// Get returns the OAuth connection for a user + provider, or nil if not found.
func (r *Repository) Get(ctx context.Context, userID, provider string) (*Connection, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, user_id, provider, email, access_token, refresh_token, scopes,
		       expires_at, created_at, updated_at
		FROM oauth_connections
		WHERE user_id = $1 AND provider = $2
	`, userID, provider)

	var c Connection
	err := row.Scan(
		&c.ID, &c.UserID, &c.Provider, &c.Email,
		&c.AccessToken, &c.RefreshToken, &c.Scopes,
		&c.ExpiresAt, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// List returns all OAuth connections for a user.
func (r *Repository) List(ctx context.Context, userID string) ([]*Connection, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, provider, email, access_token, refresh_token, scopes,
		       expires_at, created_at, updated_at
		FROM oauth_connections
		WHERE user_id = $1
		ORDER BY provider
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conns []*Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(
			&c.ID, &c.UserID, &c.Provider, &c.Email,
			&c.AccessToken, &c.RefreshToken, &c.Scopes,
			&c.ExpiresAt, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, err
		}
		conns = append(conns, &c)
	}
	return conns, rows.Err()
}

// Delete removes the OAuth connection for a user + provider.
func (r *Repository) Delete(ctx context.Context, userID, provider string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM oauth_connections WHERE user_id = $1 AND provider = $2`,
		userID, provider)
	return err
}
