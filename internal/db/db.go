// Package db manages the PostgreSQL connection pool used throughout the application.
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect creates and returns a new connection pool for the given database URL.
func Connect(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing database URL: %w", err)
	}

	config.MaxConns = 20

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	return pool, nil
}

// HealthCheck pings the database with SELECT 1.
func HealthCheck(ctx context.Context, pool *pgxpool.Pool) bool {
	if pool == nil {
		return false
	}
	var n int
	err := pool.QueryRow(ctx, "SELECT 1").Scan(&n)
	return err == nil && n == 1
}
