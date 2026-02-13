package migrate

import (
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

// ensureSchemaAccess creates a private schema (matching the DB username) and
// returns an updated DATABASE_URL with search_path set to that schema.
// This works around PostgreSQL 16 revoking CREATE on "public" for non-owners
// (common on DigitalOcean App Platform dev databases).
func ensureSchemaAccess(databaseURL string) (string, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return databaseURL, err
	}
	defer db.Close()

	// Check if we can create in public
	var canCreate bool
	err = db.QueryRow(`SELECT has_schema_privilege(current_user, 'public', 'CREATE')`).Scan(&canCreate)
	if err == nil && canCreate {
		return databaseURL, nil // public schema works fine
	}

	// Get current username to use as schema name
	var username string
	if err := db.QueryRow(`SELECT current_user`).Scan(&username); err != nil {
		return databaseURL, fmt.Errorf("failed to get current user: %w", err)
	}

	log.Printf("No CREATE on public schema, using private schema %q", username)

	// Create the user's own schema (they have permission for this)
	_, err = db.Exec(fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %q`, username))
	if err != nil {
		return databaseURL, fmt.Errorf("failed to create schema %q: %w", username, err)
	}

	// Update the DATABASE_URL to set search_path
	u, err := url.Parse(databaseURL)
	if err != nil {
		// Might be a postgres:// style DSN — try key=value approach
		if strings.Contains(databaseURL, "search_path") {
			return databaseURL, nil
		}
		return databaseURL + fmt.Sprintf("&search_path=%s,public", username), nil
	}

	q := u.Query()
	q.Set("search_path", fmt.Sprintf("%s,public", username))
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func RunMigrations(databaseURL string) error {
	log.Println("Running database migrations...")

	// Ensure we have schema access (handles DO App Platform PG 16 restrictions)
	resolvedURL, err := ensureSchemaAccess(databaseURL)
	if err != nil {
		log.Printf("Warning: schema access check failed: %v (continuing with original URL)", err)
		resolvedURL = databaseURL
	}

	// Try golang-migrate first
	err = runGolangMigrate(resolvedURL)
	if err != nil {
		log.Printf("golang-migrate failed: %v, trying direct SQL approach", err)
		return runDirectSQL(resolvedURL)
	}

	log.Println("golang-migrate completed successfully")
	return nil
}

func runGolangMigrate(databaseURL string) error {
	// Get current working directory and look for migrations folder
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	migrationsPath := filepath.Join(wd, "migrations")
	if _, err := os.Stat(migrationsPath); os.IsNotExist(err) {
		log.Println("No migrations directory found, skipping migrations")
		return nil
	}

	sourceURL := fmt.Sprintf("file://%s", migrationsPath)

	m, err := migrate.New(sourceURL, databaseURL)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	if err == migrate.ErrNoChange {
		log.Println("No new migrations to run")
	} else {
		log.Println("Migrations completed successfully")
	}

	return nil
}

func runDirectSQL(databaseURL string) error {
	log.Println("Running direct SQL migrations...")

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	migrations := []string{
		`CREATE TABLE IF NOT EXISTS accounts (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
	}

	for i, migration := range migrations {
		log.Printf("Running migration %d...", i+1)
		_, err := db.Exec(migration)
		if err != nil {
			return fmt.Errorf("failed to run migration %d: %w", i+1, err)
		}
	}

	log.Println("Direct SQL migrations completed successfully")
	return nil
}
