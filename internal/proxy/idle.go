package proxy

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// ConnectionTracker – thread-safe per-user active-connection counter
// ---------------------------------------------------------------------------

// userState holds the live connection count and the time the count last
// dropped to zero.  A zero-value lastDisconnect means there has been no
// disconnect yet (the user still has active connections).
type userState struct {
	active         int
	lastDisconnect time.Time
}

// ConnectionTracker keeps a count of active WebSocket connections per userID
// and records when a user's count drops to zero.
type ConnectionTracker struct {
	mu    sync.Mutex
	users map[string]*userState
}

// NewConnectionTracker creates a ready-to-use ConnectionTracker.
func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		users: make(map[string]*userState),
	}
}

// Connect records a new active connection for userID.
func (t *ConnectionTracker) Connect(userID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	us, ok := t.users[userID]
	if !ok {
		us = &userState{}
		t.users[userID] = us
	}
	us.active++
	// Reset the disconnect timestamp – the user is no longer idle.
	us.lastDisconnect = time.Time{}
}

// Disconnect records a closed connection for userID.
func (t *ConnectionTracker) Disconnect(userID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	us, ok := t.users[userID]
	if !ok {
		return
	}
	us.active--
	if us.active < 0 {
		us.active = 0 // defensive; should never happen
	}
	if us.active == 0 {
		us.lastDisconnect = time.Now()
	}
}

// ActiveConnections returns the number of active connections for userID.
func (t *ConnectionTracker) ActiveConnections(userID string) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	us, ok := t.users[userID]
	if !ok {
		return 0
	}
	return us.active
}

// IdleUsers returns a map of userID → time-since-last-disconnect for every
// tracked user that currently has zero active connections and has been idle
// for at least minIdle.
func (t *ConnectionTracker) IdleUsers(minIdle time.Duration) map[string]time.Duration {
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	out := make(map[string]time.Duration)
	for uid, us := range t.users {
		if us.active == 0 && !us.lastDisconnect.IsZero() {
			idle := now.Sub(us.lastDisconnect)
			if idle >= minIdle {
				out[uid] = idle
			}
		}
	}
	return out
}

// Remove deletes all tracking state for userID (call after the gateway has
// been stopped so it doesn't show up in future idle sweeps).
func (t *ConnectionTracker) Remove(userID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.users, userID)
}

// ---------------------------------------------------------------------------
// IdleMonitor – periodically stops gateways that have been idle too long
// ---------------------------------------------------------------------------

// StopGatewayFunc is the callback the IdleMonitor invokes to stop a gateway.
type StopGatewayFunc func(ctx context.Context, userID string) error

// IdleMonitorConfig holds the tunables for an IdleMonitor.
type IdleMonitorConfig struct {
	// Tracker to query for idle users.
	Tracker *ConnectionTracker

	// IdleTimeout is how long a user must have zero connections before
	// their gateway is stopped.  Required.
	IdleTimeout time.Duration

	// PollInterval is how often the monitor checks for idle users.
	// Defaults to 60 s if zero.
	PollInterval time.Duration

	// StopGateway is called (with a 30 s context) to stop an idle
	// gateway.  Required.
	StopGateway StopGatewayFunc
}

// IdleMonitor runs a background goroutine that stops idle gateways.
type IdleMonitor struct {
	cfg  IdleMonitorConfig
	stop chan struct{}
	done chan struct{}
}

// NewIdleMonitor creates and starts an IdleMonitor.  Call Stop() to shut it
// down.
func NewIdleMonitor(cfg IdleMonitorConfig) *IdleMonitor {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 60 * time.Second
	}
	m := &IdleMonitor{
		cfg:  cfg,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go m.run()
	return m
}

// Stop signals the monitor goroutine to exit and waits for it to finish.
func (m *IdleMonitor) Stop() {
	close(m.stop)
	<-m.done
}

func (m *IdleMonitor) run() {
	defer close(m.done)

	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.sweep()
		}
	}
}

func (m *IdleMonitor) sweep() {
	idle := m.cfg.Tracker.IdleUsers(m.cfg.IdleTimeout)
	for userID, dur := range idle {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		slog.Info("[idle-monitor] stopping idle gateway",
			"user", userID[:min(8, len(userID))],
			"idle", dur.Round(time.Second).String(),
		)
		if err := m.cfg.StopGateway(ctx, userID); err != nil {
			slog.Error("[idle-monitor] failed to stop gateway",
				"user", userID[:min(8, len(userID))],
				"error", err,
			)
		} else {
			// Remove tracking state so we don't attempt to stop again.
			m.cfg.Tracker.Remove(userID)
		}
		cancel()
	}
}
