package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/mchatman/bluefairy/internal/db"
)

// HealthChecker periodically probes running gateway instances.
type HealthChecker struct {
	provisioner *Provisioner
	interval    time.Duration
	maxFailures int
	cancel      context.CancelFunc
}

// NewHealthChecker creates a HealthChecker.
func NewHealthChecker(p *Provisioner, interval time.Duration, maxFailures int) *HealthChecker {
	return &HealthChecker{
		provisioner: p,
		interval:    interval,
		maxFailures: maxFailures,
	}
}

// Start begins the health check loop in a background goroutine.
func (h *HealthChecker) Start() {
	if h.cancel != nil {
		slog.Warn("[health] loop already running")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	slog.Info("[health] starting health check loop", "interval", h.interval)

	// Run immediately, then periodically.
	go func() {
		h.runCycle(ctx)

		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.runCycle(ctx)
			}
		}
	}()
}

// Stop halts the health check loop.
func (h *HealthChecker) Stop() {
	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
		slog.Info("[health] loop stopped")
	}
}

// runCycle runs one health check cycle across all running instances.
func (h *HealthChecker) runCycle(ctx context.Context) {
	pool := db.Pool()
	if pool == nil {
		return
	}

	// Only check 'running' instances. Instances in 'provisioning' status
	// still have placeholder host/port (127.0.0.1:20000) before the real
	// address is written, causing spurious health check failures.
	rows, err := pool.Query(ctx,
		`SELECT id, user_id, host, port, health_failures, started_at
		 FROM gateway_instances
		 WHERE status = 'running'`)
	if err != nil {
		slog.Error("[health] query failed", "error", err)
		return
	}
	defer rows.Close()

	type instance struct {
		id             string
		userID         string
		host           string
		port           int
		healthFailures int
		startedAt      *time.Time
	}

	var instances []instance
	for rows.Next() {
		var inst instance
		if err := rows.Scan(&inst.id, &inst.userID, &inst.host, &inst.port, &inst.healthFailures, &inst.startedAt); err != nil {
			slog.Error("[health] scan failed", "error", err)
			continue
		}
		instances = append(instances, inst)
	}
	if err := rows.Err(); err != nil {
		slog.Error("[health] rows error", "error", err)
		return
	}

	for _, inst := range instances {
		healthy, probeErr := h.probeGateway(inst.host, inst.port)

		if healthy {
			_, err := pool.Exec(ctx,
				`UPDATE gateway_instances
				 SET last_health_check_at = now(),
				     last_healthy_at = now(),
				     health_failures = 0,
				     status = 'running',
				     updated_at = now()
				 WHERE id = $1`, inst.id)
			if err != nil {
				slog.Error("[health] update healthy failed", "error", err)
			}
			continue
		}

		newFailures := inst.healthFailures + 1
		_, processAlive := h.provisioner.GetContainerID(inst.userID)

		// Grace period: don't mark as error if started within the last 60 seconds.
		// Fly machines report "started" before the app is actually listening.
		inGracePeriod := inst.startedAt != nil && time.Since(*inst.startedAt) < 60*time.Second

		if (newFailures >= h.maxFailures || !processAlive) && !inGracePeriod {
			errMsg := "Health check failed"
			if probeErr != "" {
				errMsg = probeErr
			}
			slog.Warn("[health] gateway unhealthy",
				"user", inst.userID[:min(8, len(inst.userID))],
				"failures", newFailures,
				"processAlive", processAlive,
				"error", errMsg)

			_, err := pool.Exec(ctx,
				`UPDATE gateway_instances
				 SET last_health_check_at = now(),
				     health_failures = $2,
				     status = 'error',
				     error_message = $3,
				     updated_at = now()
				 WHERE id = $1`, inst.id, newFailures, errMsg)
			if err != nil {
				slog.Error("[health] update error status failed", "error", err)
			}
		} else {
			if inGracePeriod {
				slog.Info("[health] gateway in grace period, not marking as error",
					"user", inst.userID[:min(8, len(inst.userID))],
					"failures", newFailures,
					"age", time.Since(*inst.startedAt).Round(time.Second))
			}
			// Increment failure counter but keep running.
			_, err := pool.Exec(ctx,
				`UPDATE gateway_instances
				 SET last_health_check_at = now(),
				     health_failures = $2,
				     updated_at = now()
				 WHERE id = $1`, inst.id, newFailures)
			if err != nil {
				slog.Error("[health] update failures failed", "error", err)
			}
		}
	}
}

// probeGateway checks if the gateway is accepting connections.
// Uses TCP connect probe (the gateway has no /health HTTP endpoint).
// Returns (healthy, errorMessage).
func (h *HealthChecker) probeGateway(host string, port int) (bool, string) {
	// host may already contain :port (Fly internal addresses)
	var addr string
	if strings.Contains(host, ":") {
		addr = host
	} else {
		addr = fmt.Sprintf("%s:%d", host, port)
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, err.Error()
	}
	conn.Close()
	return true, ""
}
