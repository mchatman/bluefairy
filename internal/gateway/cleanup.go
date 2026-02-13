package gateway

import (
	"context"
	"log/slog"
	"time"

	"github.com/mchatman/bluefairy/internal/db"
)

// StartTokenCleanup starts a background goroutine that periodically deletes
// expired and long-revoked refresh tokens.
func StartTokenCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				slog.Info("[cleanup] token cleanup stopped")
				return
			case <-ticker.C:
				runCleanup(ctx)
			}
		}
	}()
}

func runCleanup(ctx context.Context) {
	pool := db.Pool()
	if pool == nil {
		return
	}

	tag, err := pool.Exec(ctx,
		`DELETE FROM refresh_tokens
		 WHERE expires_at < now()
		    OR revoked_at < now() - interval '7 days'`)
	if err != nil {
		slog.Error("[cleanup] token cleanup failed", "error", err)
		return
	}

	if tag.RowsAffected() > 0 {
		slog.Info("[cleanup] deleted expired/revoked tokens", "count", tag.RowsAffected())
	}
}
