package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/mchatman/bluefairy/internal/auth"
	"github.com/mchatman/bluefairy/internal/db"
)

// Runtime is the container runtime interface (Docker or Fly).
type Runtime interface {
	Start(ctx context.Context, opts StartOpts) (*Handle, error)
	Stop(ctx context.Context, userID string) error
	IsRunning(ctx context.Context, userID string) (bool, error)
	Reconcile(ctx context.Context, userIDs []string) (alive []string, err error)
	StopAll(ctx context.Context) error
	GetID(userID string) (string, bool)
	GetTrackedUserIDs() []string
}

// StartOpts are the options passed to Runtime.Start.
type StartOpts struct {
	UserID   string
	Port     int
	StateDir string
	EnvVars  map[string]string
}

// Handle is returned by Runtime.Start.
type Handle struct {
	ID              string // container/machine ID
	InternalAddress string // host:port to proxy to
}

// ProvisionResult is returned by Provision.
type ProvisionResult struct {
	InstanceID   string
	Port         int
	StateDir     string
	GatewayToken string
}

// Provisioner manages gateway lifecycle: port allocation, config writing,
// DB updates, and delegates container operations to a Runtime.
type Provisioner struct {
	runtime             Runtime
	stateRoot           string
	nodeEnv             string
	anthropicOAuthToken string
	anthropicAPIKey     string
	proxySecret         string // shared secret for X-Proxy-Secret header validation
	remoteRuntime       bool   // true for Fly (no local state dir needed)
	mu                  sync.Mutex
	locks               map[string]chan struct{}
}

// NewProvisioner creates a new Provisioner.
func NewProvisioner(rt Runtime, stateRoot, nodeEnv, anthropicOAuthToken, anthropicAPIKey, proxySecret string, remoteRuntime bool) *Provisioner {
	return &Provisioner{
		runtime:             rt,
		stateRoot:           stateRoot,
		nodeEnv:             nodeEnv,
		anthropicOAuthToken: anthropicOAuthToken,
		anthropicAPIKey:     anthropicAPIKey,
		proxySecret:         proxySecret,
		remoteRuntime:       remoteRuntime,
		locks:               make(map[string]chan struct{}),
	}
}

// acquireLock acquires a per-user lock. It returns a release function.
func (p *Provisioner) acquireLock(userID string) func() {
	for {
		p.mu.Lock()
		ch, ok := p.locks[userID]
		if !ok {
			// No one holds the lock — create a channel and take it.
			ch = make(chan struct{})
			p.locks[userID] = ch
			p.mu.Unlock()
			return func() {
				p.mu.Lock()
				delete(p.locks, userID)
				p.mu.Unlock()
				close(ch) // wake any waiters
			}
		}
		p.mu.Unlock()
		// Wait for the current holder to release.
		<-ch
	}
}

// ReconcileOnStartup checks the DB for stale instances and reconciles
// them with the container runtime.
func (p *Provisioner) ReconcileOnStartup(ctx context.Context) error {
	pool := db.Pool()

	rows, err := pool.Query(ctx,
		`SELECT user_id FROM gateway_instances
		 WHERE status IN ('running', 'provisioning', 'stopping')`)
	if err != nil {
		return fmt.Errorf("querying stale instances: %w", err)
	}
	defer rows.Close()

	var userIDs []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			return fmt.Errorf("scanning user_id: %w", err)
		}
		userIDs = append(userIDs, uid)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating rows: %w", err)
	}

	if len(userIDs) == 0 {
		return nil
	}

	alive, err := p.runtime.Reconcile(ctx, userIDs)
	if err != nil {
		return fmt.Errorf("runtime reconcile: %w", err)
	}

	aliveSet := make(map[string]struct{}, len(alive))
	for _, uid := range alive {
		aliveSet[uid] = struct{}{}
		slog.Info("[provisioner] re-adopted running gateway", "user", uid[:min(8, len(uid))])
	}

	var reconciled int
	for _, uid := range userIDs {
		if _, ok := aliveSet[uid]; ok {
			continue
		}
		_, err := pool.Exec(ctx,
			`UPDATE gateway_instances
			 SET status = 'stopped',
			     container_id = NULL,
			     pid = NULL,
			     error_message = 'Platform restarted',
			     stopped_at = now(),
			     updated_at = now()
			 WHERE user_id = $1
			   AND status IN ('running', 'provisioning', 'stopping')`, uid)
		if err != nil {
			slog.Error("[provisioner] reconcile update failed", "user", uid[:min(8, len(uid))], "error", err)
			continue
		}
		reconciled++
	}

	if reconciled > 0 {
		slog.Info("[provisioner] reconciled stale gateways on startup", "count", reconciled)
	}
	return nil
}

// Provision starts or returns an existing gateway for a user.
func (p *Provisioner) Provision(ctx context.Context, userID, email string) (*ProvisionResult, error) {
	release := p.acquireLock(userID)
	defer release()

	pool := db.Pool()

	// 1. Check DB for existing instance (any non-error status).
	//    If the machine exists on the runtime, reuse it and its token.
	var (
		instID      string
		port        int
		containerID *string
		stateDir    string
		gwToken     string
		status      string
	)
	err := pool.QueryRow(ctx,
		`SELECT id, port, container_id, state_dir, gateway_token, status
		 FROM gateway_instances
		 WHERE user_id = $1
		 ORDER BY created_at DESC
		 LIMIT 1`, userID,
	).Scan(&instID, &port, &containerID, &stateDir, &gwToken, &status)

	if err == nil {
		// Ask the runtime about the actual machine state.
		running, rErr := p.runtime.IsRunning(ctx, userID)
		if rErr == nil && running {
			// Machine is running — update DB and return with existing token.
			_, _ = pool.Exec(ctx,
				`UPDATE gateway_instances
				 SET status = 'running', health_failures = 0, error_message = NULL,
				     started_at = COALESCE(started_at, now()), updated_at = now()
				 WHERE id = $1`, instID)
			slog.Info("[provisioner] gateway already running, reusing",
				"user", userID[:min(8, len(userID))])
			return &ProvisionResult{
				InstanceID:   instID,
				Port:         port,
				StateDir:     stateDir,
				GatewayToken: gwToken,
			}, nil
		}
	}

	// 2. Allocate a port
	var newPort int
	if err := pool.QueryRow(ctx,
		`SELECT next_available_gateway_port()`).Scan(&newPort); err != nil {
		return nil, fmt.Errorf("allocating port: %w", err)
	}

	newStateDir := filepath.Join(p.stateRoot, userID)

	// Reuse the existing token if we have one (the Fly machine has it baked
	// into its env vars and can't be changed without recreating).
	// Only generate a fresh token for truly new instances.
	newToken := gwToken
	if newToken == "" {
		newToken = auth.GenerateOpaqueToken()
	}

	// 3. Upsert the gateway_instances row (provisioning)
	var instanceID string
	err = pool.QueryRow(ctx,
		`INSERT INTO gateway_instances (user_id, host, port, gateway_token, state_dir, status)
		 VALUES ($1, '127.0.0.1', $2, $3, $4, 'provisioning')
		 ON CONFLICT (user_id) DO UPDATE SET
		   port = EXCLUDED.port,
		   gateway_token = EXCLUDED.gateway_token,
		   state_dir = EXCLUDED.state_dir,
		   status = 'provisioning',
		   error_message = NULL,
		   health_failures = 0,
		   updated_at = now()
		 RETURNING id`,
		userID, newPort, newToken, newStateDir,
	).Scan(&instanceID)
	if err != nil {
		return nil, fmt.Errorf("upserting gateway instance: %w", err)
	}

	// 4. Create state dir + write config (local runtimes only).
	//    For remote runtimes (Fly), the gateway machine has its own volume
	//    and reads config from env vars — no local state dir needed.
	if !p.remoteRuntime {
		if err := os.MkdirAll(newStateDir, 0o755); err != nil {
			return nil, fmt.Errorf("creating state dir: %w", err)
		}
		if err := WriteAwareConfig(newStateDir, userID, email, newPort, newToken, p.proxySecret); err != nil {
			return nil, fmt.Errorf("writing config: %w", err)
		}
	}

	// 5. Build env vars
	var modelEnv map[string]string
	if !p.remoteRuntime {
		modelEnv, err = ReadModelEnv(newStateDir)
		if err != nil {
			slog.Warn("[provisioner] reading model env", "error", err)
			modelEnv = map[string]string{}
		}
	} else {
		modelEnv = map[string]string{}
	}
	envVars := make(map[string]string, len(modelEnv)+6)
	for k, v := range modelEnv {
		envVars[k] = v
	}
	envVars["AWARE_HOME"] = "/data"
	envVars["AWARE_USER_ID"] = userID
	envVars["AWARE_GATEWAY_TOKEN"] = newToken
	envVars["NODE_ENV"] = p.nodeEnv
	if p.anthropicOAuthToken != "" {
		envVars["ANTHROPIC_OAUTH_TOKEN"] = p.anthropicOAuthToken
	}
	if p.anthropicAPIKey != "" {
		envVars["ANTHROPIC_API_KEY"] = p.anthropicAPIKey
	}
	if p.proxySecret != "" {
		envVars["PROXY_SECRET"] = p.proxySecret
	}

	// 6. Start the container
	handle, err := p.runtime.Start(ctx, StartOpts{
		UserID:   userID,
		Port:     newPort,
		StateDir: newStateDir,
		EnvVars:  envVars,
	})
	if err != nil {
		slog.Error("[provisioner] failed to start container",
			"user", userID[:min(8, len(userID))], "error", err)
		_, _ = pool.Exec(ctx,
			`UPDATE gateway_instances
			 SET status = 'error',
			     error_message = $2,
			     stopped_at = now(),
			     updated_at = now()
			 WHERE id = $1`, instanceID, err.Error())
		return nil, fmt.Errorf("starting container: %w", err)
	}

	// 7. Update DB — running (store internal address for proxy routing)
	_, err = pool.Exec(ctx,
		`UPDATE gateway_instances
		 SET container_id = $2,
		     host = $3,
		     status = 'running',
		     started_at = now(),
		     stopped_at = NULL,
		     updated_at = now()
		 WHERE id = $1`, instanceID, handle.ID, handle.InternalAddress)
	if err != nil {
		slog.Error("[provisioner] DB update after start failed", "error", err)
	}

	slog.Info("[provisioner] gateway ready",
		"user", userID[:min(8, len(userID))],
		"address", handle.InternalAddress,
		"container", handle.ID)

	return &ProvisionResult{
		InstanceID:   instanceID,
		Port:         newPort,
		StateDir:     newStateDir,
		GatewayToken: newToken,
	}, nil
}

// Stop stops a user's gateway.
func (p *Provisioner) Stop(ctx context.Context, userID string) error {
	pool := db.Pool()

	_, err := pool.Exec(ctx,
		`UPDATE gateway_instances
		 SET status = 'stopping', updated_at = now()
		 WHERE user_id = $1 AND status IN ('running', 'provisioning')`, userID)
	if err != nil {
		slog.Error("[provisioner] stop: DB update failed", "error", err)
	}

	if err := p.runtime.Stop(ctx, userID); err != nil {
		slog.Error("[provisioner] stop: runtime stop failed",
			"user", userID[:min(8, len(userID))], "error", err)
	}

	_, err = pool.Exec(ctx,
		`UPDATE gateway_instances
		 SET status = 'stopped',
		     container_id = NULL,
		     pid = NULL,
		     stopped_at = now(),
		     updated_at = now()
		 WHERE user_id = $1 AND status IN ('stopping', 'running', 'provisioning')`, userID)
	if err != nil {
		return fmt.Errorf("stop: final DB update: %w", err)
	}

	return nil
}

// Restart stops then re-provisions a user's gateway.
func (p *Provisioner) Restart(ctx context.Context, userID, email string) (*ProvisionResult, error) {
	if err := p.Stop(ctx, userID); err != nil {
		slog.Warn("[provisioner] restart: stop phase failed",
			"user", userID[:min(8, len(userID))], "error", err)
	}
	return p.Provision(ctx, userID, email)
}

// ShutdownAll stops all tracked gateways (graceful shutdown).
func (p *Provisioner) ShutdownAll(ctx context.Context) error {
	uids := p.runtime.GetTrackedUserIDs()
	slog.Info("[provisioner] shutting down all gateways", "count", len(uids))
	if err := p.runtime.StopAll(ctx); err != nil {
		return fmt.Errorf("stopping all: %w", err)
	}
	slog.Info("[provisioner] all gateways stopped")
	return nil
}

// GetGateway returns the internal address and gateway token for a running gateway.
// Used by the proxy layer to route requests.
func (p *Provisioner) GetGateway(userID string) (addr string, gatewayToken string, ok bool) {
	pool := db.Pool()
	var host string
	var port int
	err := pool.QueryRow(context.Background(),
		`SELECT host, port, gateway_token
		 FROM gateway_instances
		 WHERE user_id = $1 AND status = 'running'
		 LIMIT 1`, userID,
	).Scan(&host, &port, &gatewayToken)
	if err != nil {
		return "", "", false
	}
	// host may already contain :port (Fly internal addresses)
	if strings.Contains(host, ":") {
		return host, gatewayToken, true
	}
	return host + ":" + strconv.Itoa(port), gatewayToken, true
}

// GetContainerID returns the runtime ID for a user's gateway.
func (p *Provisioner) GetContainerID(userID string) (string, bool) {
	return p.runtime.GetID(userID)
}

// GetTrackedUserIDs returns all users with active gateways tracked by the runtime.
func (p *Provisioner) GetTrackedUserIDs() []string {
	return p.runtime.GetTrackedUserIDs()
}

// OnContainerExit is called by the runtime when a container dies.
// It updates the DB to reflect the exit.
func (p *Provisioner) OnContainerExit(userID string, exitCode string) {
	var (
		newStatus string
		errorMsg  *string
	)
	if exitCode == "0" || exitCode == "" {
		newStatus = "stopped"
	} else {
		newStatus = "error"
		msg := fmt.Sprintf("Container exited with code %s", exitCode)
		errorMsg = &msg
	}

	_, err := db.Pool().Exec(context.Background(),
		`UPDATE gateway_instances
		 SET status = $2,
		     container_id = NULL,
		     pid = NULL,
		     error_message = $3,
		     stopped_at = now(),
		     updated_at = now()
		 WHERE user_id = $1
		   AND status IN ('running', 'provisioning')`,
		userID, newStatus, errorMsg)
	if err != nil {
		slog.Error("[provisioner] failed to update exit status",
			"user", userID[:min(8, len(userID))], "error", err)
	}
}
