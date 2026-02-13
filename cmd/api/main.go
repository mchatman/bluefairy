package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mchatman/bluefairy/internal/config"
	"github.com/mchatman/bluefairy/internal/db"
	"github.com/mchatman/bluefairy/internal/migrate"
	"github.com/jackc/pgx/v5/pgxpool"
)

type App struct {
	router http.Handler
	config *config.Config
	pool   *pgxpool.Pool
}

func New(cfg *config.Config, pool *pgxpool.Pool) *App {
	app := &App{
		config: cfg,
		pool:   pool,
	}

	app.loadRoutes()

	return app
}

func (a *App) Start(ctx context.Context) error {
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", a.config.Port),
		Handler:      a.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErr := make(chan error, 1)

	go func() {
		log.Printf("Starting server on port %d...", a.config.Port)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		return err
	case <-stop:
		log.Println("Shutdown signal received")
	case <-ctx.Done():
		log.Println("Context cancelled")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		if closeErr := server.Close(); closeErr != nil {
			return errors.Join(err, closeErr)
		}
		return err
	}

	log.Println("Server exited gracefully")
	return nil
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	ctx := context.Background()
	if err := db.Connect(ctx, cfg.DatabaseURL); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Run database migrations
	if err := migrate.RunMigrations(cfg.DatabaseURL); err != nil {
		log.Printf("Warning: Failed to run migrations: %v", err)
		// Don't fail startup - migrations might already be applied
	}

	pool := db.Pool()
	app := New(cfg, pool)

	if err := app.Start(context.Background()); err != nil {
		log.Fatal(err)
	}
}