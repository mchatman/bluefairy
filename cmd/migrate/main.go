package main

import (
	"fmt"
	"log"
	"os"

	"github.com/mchatman/bluefairy/internal/migrate"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run cmd/migrate/main.go <DATABASE_URL>")
	}

	databaseURL := os.Args[1]

	fmt.Printf("Running migrations against: %s\n", databaseURL)

	if err := migrate.RunMigrations(databaseURL); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	fmt.Println("Migrations completed successfully!")
}