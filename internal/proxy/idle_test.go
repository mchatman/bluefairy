package proxy

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestConnectionTracker_ConnectDisconnect(t *testing.T) {
	tr := NewConnectionTracker()

	tr.Connect("u1")
	tr.Connect("u1")
	tr.Connect("u2")

	if got := tr.ActiveConnections("u1"); got != 2 {
		t.Fatalf("u1: want 2, got %d", got)
	}
	if got := tr.ActiveConnections("u2"); got != 1 {
		t.Fatalf("u2: want 1, got %d", got)
	}

	tr.Disconnect("u1")
	if got := tr.ActiveConnections("u1"); got != 1 {
		t.Fatalf("u1 after disconnect: want 1, got %d", got)
	}

	tr.Disconnect("u1")
	if got := tr.ActiveConnections("u1"); got != 0 {
		t.Fatalf("u1 after 2nd disconnect: want 0, got %d", got)
	}
}

func TestConnectionTracker_IdleUsers(t *testing.T) {
	tr := NewConnectionTracker()

	// u1: connect then disconnect → should appear idle.
	tr.Connect("u1")
	tr.Disconnect("u1")

	// u2: still connected → should NOT appear idle.
	tr.Connect("u2")

	// Give a tiny moment so idle duration > 0.
	time.Sleep(5 * time.Millisecond)

	idle := tr.IdleUsers(0)
	if _, ok := idle["u1"]; !ok {
		t.Fatal("u1 should be idle")
	}
	if _, ok := idle["u2"]; ok {
		t.Fatal("u2 should NOT be idle")
	}

	// With a high minIdle, nothing should be idle.
	idle = tr.IdleUsers(1 * time.Hour)
	if len(idle) != 0 {
		t.Fatalf("expected no idle users with 1h min, got %d", len(idle))
	}
}

func TestConnectionTracker_Remove(t *testing.T) {
	tr := NewConnectionTracker()
	tr.Connect("u1")
	tr.Disconnect("u1")
	tr.Remove("u1")

	if got := tr.ActiveConnections("u1"); got != 0 {
		t.Fatalf("u1 after remove: want 0, got %d", got)
	}
	idle := tr.IdleUsers(0)
	if len(idle) != 0 {
		t.Fatal("removed user should not appear idle")
	}
}

func TestIdleMonitor_StopsIdleGateway(t *testing.T) {
	tr := NewConnectionTracker()

	// Simulate a connection that is already closed.
	tr.Connect("u1")
	tr.Disconnect("u1")

	// Backdate the disconnect so the idle timeout is exceeded.
	tr.mu.Lock()
	tr.users["u1"].lastDisconnect = time.Now().Add(-10 * time.Minute)
	tr.mu.Unlock()

	var mu sync.Mutex
	stopped := []string{}

	m := NewIdleMonitor(IdleMonitorConfig{
		Tracker:      tr,
		IdleTimeout:  5 * time.Minute,
		PollInterval: 50 * time.Millisecond, // fast for testing
		StopGateway: func(_ context.Context, userID string) error {
			mu.Lock()
			stopped = append(stopped, userID)
			mu.Unlock()
			return nil
		},
	})

	// Wait for at least one sweep.
	time.Sleep(200 * time.Millisecond)
	m.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(stopped) == 0 {
		t.Fatal("expected idle monitor to stop u1")
	}
	if stopped[0] != "u1" {
		t.Fatalf("expected u1, got %s", stopped[0])
	}

	// After stop, the user should be removed from the tracker.
	if got := tr.ActiveConnections("u1"); got != 0 {
		t.Fatalf("u1 should be removed, got %d active", got)
	}
}

func TestIdleMonitor_DoesNotStopActiveUser(t *testing.T) {
	tr := NewConnectionTracker()
	tr.Connect("u1") // still active

	stopped := false
	m := NewIdleMonitor(IdleMonitorConfig{
		Tracker:      tr,
		IdleTimeout:  1 * time.Millisecond,
		PollInterval: 50 * time.Millisecond,
		StopGateway: func(_ context.Context, userID string) error {
			stopped = true
			return nil
		},
	})

	time.Sleep(200 * time.Millisecond)
	m.Stop()

	if stopped {
		t.Fatal("should not stop a user with active connections")
	}
}
