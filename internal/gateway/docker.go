package gateway

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const containerPrefix = "aware-gw-"

// DockerRuntime implements Runtime using the Docker CLI.
type DockerRuntime struct {
	image      string
	containers map[string]string          // userID → containerID
	monitors   map[string]context.CancelFunc // userID → cancel monitor
	mu         sync.RWMutex
	onExit     func(userID string, exitCode string)
}

// NewDockerRuntime creates a DockerRuntime for the given image.
func NewDockerRuntime(image string) *DockerRuntime {
	return &DockerRuntime{
		image:      image,
		containers: make(map[string]string),
		monitors:   make(map[string]context.CancelFunc),
	}
}

// SetOnExit sets the callback invoked when a container exits unexpectedly.
func (d *DockerRuntime) SetOnExit(fn func(userID string, exitCode string)) {
	d.onExit = fn
}

func containerName(userID string) string {
	id := userID
	if len(id) > 12 {
		id = id[:12]
	}
	return containerPrefix + id
}

// docker runs a docker CLI command and returns stdout.
func docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w (stderr: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// dockerSafe runs a docker command, returning "" on error.
func dockerSafe(ctx context.Context, args ...string) string {
	out, _ := docker(ctx, args...)
	return out
}

// waitForPort polls until a TCP connection succeeds on the given port.
func waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("port %d not ready after %v", port, timeout)
}

// Start creates and runs a Docker container for the user.
func (d *DockerRuntime) Start(ctx context.Context, opts StartOpts) (*Handle, error) {
	name := containerName(opts.UserID)

	// Remove any stale container with the same name.
	dockerSafe(ctx, "rm", "-f", name)

	args := []string{
		"run", "-d",
		"--name", name,
		"--network", "host",
		"--init",
		"--restart", "unless-stopped",
		"-v", fmt.Sprintf("%s:/data", opts.StateDir),
		"--memory", "512m",
		"--memory-swap", "768m",
		"--cpus", "1.0",
	}

	for k, v := range opts.EnvVars {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	args = append(args,
		d.image,
		"gateway", "run",
		"--port", fmt.Sprintf("%d", opts.Port),
		"--bind", "loopback",
		"--force",
	)

	containerID, err := docker(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("docker run: %w", err)
	}
	if len(containerID) > 12 {
		containerID = containerID[:12]
	}

	d.mu.Lock()
	d.containers[opts.UserID] = containerID
	d.mu.Unlock()

	// Wait for the gateway to accept connections.
	if err := waitForPort(opts.Port, 20*time.Second); err != nil {
		dockerSafe(ctx, "stop", "-t", "5", name)
		dockerSafe(ctx, "rm", "-f", name)
		d.mu.Lock()
		delete(d.containers, opts.UserID)
		d.mu.Unlock()
		return nil, fmt.Errorf("gateway failed to start listening on port %d: %w", opts.Port, err)
	}

	d.startMonitor(opts.UserID, name)

	return &Handle{
		ID:              containerID,
		InternalAddress: fmt.Sprintf("127.0.0.1:%d", opts.Port),
	}, nil
}

// Stop stops and removes a user's Docker container.
func (d *DockerRuntime) Stop(ctx context.Context, userID string) error {
	name := containerName(userID)
	d.stopMonitor(userID)

	// Best-effort stop.
	_, _ = docker(ctx, "stop", "-t", "10", name)
	dockerSafe(ctx, "rm", "-f", name)

	d.mu.Lock()
	delete(d.containers, userID)
	d.mu.Unlock()

	return nil
}

// IsRunning checks if the user's container is running.
func (d *DockerRuntime) IsRunning(ctx context.Context, userID string) (bool, error) {
	out, err := docker(ctx, "inspect", "-f", "{{.State.Running}}", containerName(userID))
	if err != nil {
		return false, nil // container doesn't exist
	}
	return out == "true", nil
}

// Reconcile checks which containers are still alive and re-adopts them.
func (d *DockerRuntime) Reconcile(ctx context.Context, userIDs []string) ([]string, error) {
	var alive []string
	for _, uid := range userIDs {
		name := containerName(uid)
		running, _ := d.IsRunning(ctx, uid)
		if running {
			cid := dockerSafe(ctx, "inspect", "-f", "{{.Id}}", name)
			if cid != "" {
				if len(cid) > 12 {
					cid = cid[:12]
				}
				d.mu.Lock()
				d.containers[uid] = cid
				d.mu.Unlock()
				d.startMonitor(uid, name)
				alive = append(alive, uid)
			}
		} else {
			// Clean up dead container.
			dockerSafe(ctx, "rm", "-f", name)
		}
	}
	return alive, nil
}

// StopAll stops all tracked containers.
func (d *DockerRuntime) StopAll(ctx context.Context) error {
	d.mu.RLock()
	uids := make([]string, 0, len(d.containers))
	for uid := range d.containers {
		uids = append(uids, uid)
	}
	d.mu.RUnlock()

	var wg sync.WaitGroup
	for _, uid := range uids {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			_ = d.Stop(ctx, u)
		}(uid)
	}
	wg.Wait()
	return nil
}

// GetID returns the container ID for the given user.
func (d *DockerRuntime) GetID(userID string) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	id, ok := d.containers[userID]
	return id, ok
}

// GetTrackedUserIDs returns all user IDs with tracked containers.
func (d *DockerRuntime) GetTrackedUserIDs() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	uids := make([]string, 0, len(d.containers))
	for uid := range d.containers {
		uids = append(uids, uid)
	}
	return uids
}

// startMonitor starts a background goroutine that polls the container every
// 10 seconds. If the container is no longer running, it invokes the onExit
// callback and cleans up tracking state.
func (d *DockerRuntime) startMonitor(userID, name string) {
	d.stopMonitor(userID)

	ctx, cancel := context.WithCancel(context.Background())
	d.mu.Lock()
	d.monitors[userID] = cancel
	d.mu.Unlock()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				running, _ := d.IsRunning(context.Background(), userID)
				if !running {
					d.mu.Lock()
					delete(d.containers, userID)
					delete(d.monitors, userID)
					d.mu.Unlock()
					cancel()

					exitCode := dockerSafe(context.Background(), "inspect", "-f", "{{.State.ExitCode}}", name)
					slog.Warn("[docker] container exited",
						"name", name, "exitCode", exitCode)

					if d.onExit != nil {
						d.onExit(userID, exitCode)
					}
					return
				}
			}
		}
	}()
}

// stopMonitor cancels the monitor goroutine for a user.
func (d *DockerRuntime) stopMonitor(userID string) {
	d.mu.Lock()
	if cancel, ok := d.monitors[userID]; ok {
		cancel()
		delete(d.monitors, userID)
	}
	d.mu.Unlock()
}
