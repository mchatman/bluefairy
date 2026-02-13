package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool

// Connect initializes the connection pool.
func Connect(ctx context.Context, databaseURL string) error {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("parsing database URL: %w", err)
	}

	config.MaxConns = 20

	p, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("creating connection pool: %w", err)
	}

	pool = p
	return nil
}

// Pool returns the connection pool.
func Pool() *pgxpool.Pool {
	return pool
}

// HealthCheck pings the database with SELECT 1.
func HealthCheck(ctx context.Context) bool {
	if pool == nil {
		return false
	}
	var n int
	err := pool.QueryRow(ctx, "SELECT 1").Scan(&n)
	return err == nil && n == 1
}

// Close gracefully closes the connection pool.
func Close() {
	if pool != nil {
		pool.Close()
	}
}
