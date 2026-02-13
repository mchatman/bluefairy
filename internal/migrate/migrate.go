package migrate

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

// findWritableSchema probes for a schema the current user can CREATE in.
// Returns the schema name or empty string if none found.
func findWritableSchema(db *sql.DB) string {
	// Check public first
	var canCreate bool
	err := db.QueryRow(`SELECT has_schema_privilege(current_user, 'public', 'CREATE')`).Scan(&canCreate)
	if err == nil && canCreate {
		return ""
	}

	// Look for any schema the user owns or has CREATE on
	rows, err := db.Query(`
		SELECT n.nspname FROM pg_namespace n
		WHERE n.nspname NOT LIKE 'pg_%'
		  AND n.nspname != 'information_schema'
		  AND has_schema_privilege(current_user, n.nspname, 'CREATE')
		ORDER BY
		  CASE WHEN n.nspname = 'public' THEN 1 ELSE 0 END,
		  n.nspname
	`)
	if err != nil {
		return ""
	}
	defer rows.Close()

	for rows.Next() {
		var s string
		if rows.Scan(&s) == nil {
			log.Printf("Found writable schema: %q", s)
			return s
		}
	}
	return ""
}

func RunMigrations(databaseURL string) error {
	log.Println("Running database migrations...")

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// Find a writable schema and set search_path on the connection
	schema := findWritableSchema(db)
	if schema != "" && schema != "public" {
		log.Printf("No CREATE on public, switching search_path to %q", schema)
		_, err = db.Exec(fmt.Sprintf(`SET search_path TO %s, public`, schema))
		if err != nil {
			log.Printf("Warning: failed to set search_path: %v", err)
		}
	}

	// Try golang-migrate with WithInstance so our search_path sticks
	err = runGolangMigrate(db)
	if err != nil {
		log.Printf("golang-migrate failed: %v, trying direct SQL approach", err)
		return runDirectSQL(db)
	}

	log.Println("golang-migrate completed successfully")
	return nil
}

func runGolangMigrate(db *sql.DB) error {
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

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create postgres driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(sourceURL, "postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}
	// Don't defer m.Close() — it would close the shared db connection

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

func runDirectSQL(db *sql.DB) error {
	log.Println("Running direct SQL migrations...")

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
