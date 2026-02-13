package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Fly Machines Runtime
//
// Runs per-user gateways as Fly Machines. Each user gets a persistent
// machine + volume that is started/stopped on demand.
//
// The Fly Machines API is the source of truth. The in-memory cache is
// an optimisation to avoid API calls on hot paths, but all methods
// fall back to the API when the cache misses.
//
// Internal routing: {machineID}.vm.{app}.internal:18789
// ---------------------------------------------------------------------------

const flyAPIBase = "https://api.machines.dev/v1"

// FlyConfig holds configuration for the Fly runtime.
type FlyConfig struct {
	Token       string // FLY_API_TOKEN
	App         string // FLY_GATEWAY_APP
	Region      string // FLY_GATEWAY_REGION
	Image       string // FLY_GATEWAY_IMAGE
	IdleTimeout time.Duration
}

// FlyRuntime implements Runtime using the Fly Machines API.
type FlyRuntime struct {
	cfg    FlyConfig
	client *http.Client
	cache  map[string]flyEntry // userID → {machineID, volumeID} — cache only
	mu     sync.RWMutex
}

type flyEntry struct {
	MachineID string
	VolumeID  string
}

// NewFlyRuntime creates a new Fly Machines runtime.
func NewFlyRuntime(cfg FlyConfig) *FlyRuntime {
	return &FlyRuntime{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		cache:  make(map[string]flyEntry),
	}
}

// ---------------------------------------------------------------------------
// Runtime interface
// ---------------------------------------------------------------------------

func (f *FlyRuntime) Start(ctx context.Context, opts StartOpts) (*Handle, error) {
	name := flyMachineName(opts.UserID)

	// Look up existing machine: cache first, then Fly API.
	machine, err := f.findMachineForUser(ctx, opts.UserID)
	if err != nil {
		slog.Warn("[fly] error looking up machine", "name", name, "error", err)
		// Fall through to create.
	}

	if machine != nil {
		switch machine.State {
		case "started":
			slog.Info("[fly] machine already running", "name", name, "id", machine.ID)
			return f.handle(machine.ID), nil

		case "stopped":
			// Update image/init if outdated before starting.
			if f.needsUpdate(*machine) {
				slog.Info("[fly] updating machine before start",
					"name", name, "id", machine.ID,
					"oldImage", machine.Config.Image, "newImage", f.cfg.Image)
				cfg := f.machineConfig(machine.Config.Env, "")
				if md, ok := cfg["metadata"].(map[string]string); ok {
					for k, v := range machine.Config.Metadata {
						md[k] = v
					}
				}
				if err := f.updateMachine(ctx, machine.ID, cfg); err != nil {
					slog.Warn("[fly] machine update failed, starting with old config",
						"name", name, "error", err)
				}
			}

			slog.Info("[fly] waking stopped machine", "name", name, "id", machine.ID)
			if err := f.startMachine(ctx, machine.ID); err != nil {
				return nil, fmt.Errorf("starting machine: %w", err)
			}
			if err := f.waitForState(ctx, machine.ID, "started", 30*time.Second); err != nil {
				return nil, fmt.Errorf("waiting for machine start: %w", err)
			}
			h := f.handle(machine.ID)
			f.waitForHealthy(h.InternalAddress, 60*time.Second)
			return h, nil

		default:
			// Machine in bad state — destroy and recreate.
			slog.Warn("[fly] machine in unexpected state, destroying",
				"name", name, "id", machine.ID, "state", machine.State)
			_ = f.destroyMachine(ctx, machine.ID)
			f.cacheRemove(opts.UserID)
		}
	}

	// No existing machine — create a new one.
	volName := flyVolumeName(opts.UserID)
	volumeID, err := f.ensureVolume(ctx, volName)
	if err != nil {
		return nil, fmt.Errorf("ensuring volume: %w", err)
	}

	slog.Info("[fly] creating machine", "name", name, "region", f.cfg.Region)
	newMachine, err := f.createMachine(ctx, name, volumeID, opts.EnvVars)
	if err != nil {
		if isConflictError(err) {
			// Race condition: another platform instance created it. Adopt.
			slog.Warn("[fly] machine already exists (409), adopting", "name", name)
			return f.adoptExistingMachine(ctx, name, opts.UserID)
		}
		return nil, fmt.Errorf("creating machine: %w", err)
	}

	if err := f.waitForState(ctx, newMachine.ID, "started", 30*time.Second); err != nil {
		return nil, fmt.Errorf("waiting for machine start: %w", err)
	}

	f.cacheSet(opts.UserID, flyEntry{MachineID: newMachine.ID, VolumeID: volumeID})

	h := f.handle(newMachine.ID)
	f.waitForHealthy(h.InternalAddress, 60*time.Second)

	slog.Info("[fly] machine started", "name", name, "id", newMachine.ID, "region", newMachine.Region)
	return h, nil
}

func (f *FlyRuntime) Stop(ctx context.Context, userID string) error {
	machine, err := f.findMachineForUser(ctx, userID)
	if err != nil || machine == nil {
		return nil
	}
	if machine.State != "started" {
		return nil
	}
	if err := f.stopMachine(ctx, machine.ID); err != nil {
		return err
	}
	return f.waitForState(ctx, machine.ID, "stopped", 15*time.Second)
}

func (f *FlyRuntime) IsRunning(ctx context.Context, userID string) (bool, error) {
	machine, err := f.findMachineForUser(ctx, userID)
	if err != nil {
		return false, err
	}
	if machine == nil {
		return false, nil
	}
	return machine.State == "started", nil
}

func (f *FlyRuntime) Reconcile(ctx context.Context, _ []string) ([]string, error) {
	machines, err := f.listMachines(ctx)
	if err != nil {
		return nil, err
	}
	volumes, err := f.listVolumes(ctx)
	if err != nil {
		return nil, err
	}

	volByMachine := make(map[string]string)
	for _, v := range volumes {
		if v.AttachedMachineID != "" {
			volByMachine[v.AttachedMachineID] = v.ID
		}
	}

	var alive []string
	var updated int
	f.mu.Lock()
	for _, m := range machines {
		userID := m.Config.Metadata["user_id"]
		if userID == "" {
			continue
		}
		f.cache[userID] = flyEntry{
			MachineID: m.ID,
			VolumeID:  volByMachine[m.ID],
		}
		if m.State == "started" {
			alive = append(alive, userID)
			slog.Info("[fly] re-adopted running machine", "name", m.Name, "id", m.ID)
		} else {
			slog.Info("[fly] found stopped machine", "name", m.Name, "user", userID[:8])
		}

		// Update stopped machines with outdated image or init command.
		// Running machines will pick up the update on next stop/start cycle.
		if m.State == "stopped" && f.needsUpdate(m) {
			slog.Info("[fly] updating machine config",
				"name", m.Name, "id", m.ID,
				"oldImage", m.Config.Image, "newImage", f.cfg.Image)
			cfg := f.machineConfig(m.Config.Env, volByMachine[m.ID])
			// Preserve existing metadata.
			if md, ok := cfg["metadata"].(map[string]string); ok {
				for k, v := range m.Config.Metadata {
					md[k] = v
				}
			}
			if err := f.updateMachine(ctx, m.ID, cfg); err != nil {
				slog.Error("[fly] failed to update machine",
					"name", m.Name, "error", err)
			} else {
				updated++
			}
		}
	}
	f.mu.Unlock()

	if updated > 0 {
		slog.Info("[fly] updated machine configs on reconcile", "count", updated)
	}

	return alive, nil
}

func (f *FlyRuntime) StopAll(ctx context.Context) error {
	machines, err := f.listMachines(ctx)
	if err != nil {
		slog.Warn("[fly] StopAll: failed to list machines", "error", err)
		return err
	}
	for _, m := range machines {
		if m.State != "started" {
			continue
		}
		userID := m.Config.Metadata["user_id"]
		if err := f.stopMachine(ctx, m.ID); err != nil {
			slog.Warn("[fly] failed to stop machine", "user", userID[:min(8, len(userID))], "error", err)
		}
	}
	return nil
}

func (f *FlyRuntime) GetID(userID string) (string, bool) {
	f.mu.RLock()
	e, ok := f.cache[userID]
	f.mu.RUnlock()
	if ok {
		return e.MachineID, true
	}
	// Cache miss — try the Fly API (best-effort, non-blocking context).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	machine, err := f.findMachineByName(ctx, flyMachineName(userID), userID)
	if err != nil || machine == nil {
		return "", false
	}
	return machine.ID, true
}

func (f *FlyRuntime) GetTrackedUserIDs() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	ids := make([]string, 0, len(f.cache))
	for k := range f.cache {
		ids = append(ids, k)
	}
	return ids
}

// ---------------------------------------------------------------------------
// Machine lookup: cache → Fly API
// ---------------------------------------------------------------------------

// findMachineForUser returns the Fly machine for a user, checking the cache
// first and falling back to the API. Returns nil if no machine exists.
func (f *FlyRuntime) findMachineForUser(ctx context.Context, userID string) (*flyMachine, error) {
	// 1. Try the cache — query the API for current state using the cached ID.
	f.mu.RLock()
	entry, cached := f.cache[userID]
	f.mu.RUnlock()

	if cached {
		machine, err := f.getMachine(ctx, entry.MachineID)
		if err == nil {
			return machine, nil
		}
		// Machine gone (404 etc.) — clear cache, fall through to name lookup.
		slog.Info("[fly] cached machine not found, clearing cache",
			"id", entry.MachineID, "error", err)
		f.cacheRemove(userID)
	}

	// 2. Cache miss — search by machine name.
	name := flyMachineName(userID)
	machine, err := f.findMachineByName(ctx, name, userID)
	if err != nil {
		return nil, err
	}
	return machine, nil
}

// findMachineByName lists all machines and finds one matching the expected name.
// If found, it populates the cache.
func (f *FlyRuntime) findMachineByName(ctx context.Context, name, userID string) (*flyMachine, error) {
	machines, err := f.listMachines(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing machines: %w", err)
	}
	for i, m := range machines {
		if m.Name == name {
			f.cacheSet(userID, flyEntry{MachineID: m.ID})
			return &machines[i], nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Cache helpers
// ---------------------------------------------------------------------------

func (f *FlyRuntime) cacheSet(userID string, entry flyEntry) {
	f.mu.Lock()
	f.cache[userID] = entry
	f.mu.Unlock()
}

func (f *FlyRuntime) cacheRemove(userID string) {
	f.mu.Lock()
	delete(f.cache, userID)
	f.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (f *FlyRuntime) handle(machineID string) *Handle {
	return &Handle{
		ID:              machineID,
		InternalAddress: fmt.Sprintf("%s.vm.%s.internal:18789", machineID, f.cfg.App),
	}
}

// waitForHealthy polls the gateway's TCP port until it accepts connections.
func (f *FlyRuntime) waitForHealthy(addr string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			slog.Info("[fly] gateway healthy", "addr", addr)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	slog.Warn("[fly] gateway did not become healthy within timeout", "addr", addr, "timeout", timeout)
}

func isConflictError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "409")
}

// adoptExistingMachine finds a machine by name and ensures it's running.
func (f *FlyRuntime) adoptExistingMachine(ctx context.Context, name, userID string) (*Handle, error) {
	machine, err := f.findMachineByName(ctx, name, userID)
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, fmt.Errorf("machine %s not found after 409 conflict", name)
	}

	switch machine.State {
	case "started":
		// Already running.
	case "stopped":
		if err := f.startMachine(ctx, machine.ID); err != nil {
			return nil, fmt.Errorf("starting adopted machine: %w", err)
		}
		if err := f.waitForState(ctx, machine.ID, "started", 30*time.Second); err != nil {
			return nil, fmt.Errorf("waiting for adopted machine: %w", err)
		}
	default:
		if err := f.waitForState(ctx, machine.ID, "started", 30*time.Second); err != nil {
			return nil, fmt.Errorf("waiting for adopted machine (state=%s): %w", machine.State, err)
		}
	}

	h := f.handle(machine.ID)
	if machine.State != "started" {
		f.waitForHealthy(h.InternalAddress, 60*time.Second)
	}

	slog.Info("[fly] adopted existing machine", "name", name, "id", machine.ID, "state", machine.State)
	return h, nil
}

func flyMachineName(userID string) string {
	return "aware-gw-" + userID[:12]
}

func flyVolumeName(userID string) string {
	return "gw_data_" + strings.ReplaceAll(userID, "-", "")[:12]
}

// gatewayInitCmd is the shell command baked into every gateway machine.
// It writes the aware.json config and starts the gateway process.
const gatewayInitCmd = `mkdir -p /data/.aware && ` +
	`echo '{"gateway":{"mode":"local","bind":"custom","customBindHost":"::","trustedProxies":["fdaa::/16","172.16.0.0/12","10.0.0.0/8"],"controlUi":{"dangerouslyDisableDeviceAuth":true}}}' > /data/.aware/aware.json && ` +
	`exec node dist/index.js gateway run --port 18789`

// machineConfig returns the config block shared by create and update.
// envVars and volumeID are only needed for create; pass nil/"" for update.
func (f *FlyRuntime) machineConfig(envVars map[string]string, volumeID string) map[string]interface{} {
	cfg := map[string]interface{}{
		"image": f.cfg.Image,
		"init": map[string]interface{}{
			"entrypoint": []string{"/bin/sh", "-c"},
			"cmd":        []string{gatewayInitCmd},
		},
		"guest": map[string]interface{}{
			"cpu_kind":  "shared",
			"cpus":      1,
			"memory_mb": 512,
		},
		"auto_destroy": false,
		"metadata": map[string]string{
			"managed_by": "aware-platform",
		},
	}
	if envVars != nil {
		cfg["env"] = envVars
		if md, ok := cfg["metadata"].(map[string]string); ok {
			if uid := envVars["AWARE_USER_ID"]; uid != "" {
				md["user_id"] = uid
			}
		}
	}
	if volumeID != "" {
		cfg["mounts"] = []map[string]interface{}{
			{"volume": volumeID, "path": "/data"},
		}
	}
	return cfg
}

// ---------------------------------------------------------------------------
// Fly Machines API types
// ---------------------------------------------------------------------------

type flyMachine struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Region string `json:"region"`
	Config struct {
		Image    string            `json:"image"`
		Env      map[string]string `json:"env"`
		Metadata map[string]string `json:"metadata"`
		Init     struct {
			Entrypoint []string `json:"entrypoint"`
			Cmd        []string `json:"cmd"`
		} `json:"init"`
	} `json:"config"`
}

type flyVolume struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	State             string `json:"state"`
	Region            string `json:"region"`
	AttachedMachineID string `json:"attached_machine_id"`
}

// ---------------------------------------------------------------------------
// Fly Machines API calls
// ---------------------------------------------------------------------------

func (f *FlyRuntime) apiRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s/apps/%s%s", flyAPIBase, f.cfg.App, path)

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+f.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fly API %s %s: %d %s", method, path, resp.StatusCode, string(errBody))
	}
	return resp, nil
}

func (f *FlyRuntime) listMachines(ctx context.Context) ([]flyMachine, error) {
	resp, err := f.apiRequest(ctx, "GET", "/machines", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var machines []flyMachine
	return machines, json.NewDecoder(resp.Body).Decode(&machines)
}

func (f *FlyRuntime) getMachine(ctx context.Context, id string) (*flyMachine, error) {
	resp, err := f.apiRequest(ctx, "GET", "/machines/"+id, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var m flyMachine
	return &m, json.NewDecoder(resp.Body).Decode(&m)
}

func (f *FlyRuntime) getMachineState(ctx context.Context, id string) (string, error) {
	m, err := f.getMachine(ctx, id)
	if err != nil {
		return "", err
	}
	return m.State, nil
}

func (f *FlyRuntime) createMachine(ctx context.Context, name, volumeID string, envVars map[string]string) (*flyMachine, error) {
	body := map[string]interface{}{
		"name":   name,
		"region": f.cfg.Region,
		"config": f.machineConfig(envVars, volumeID),
	}

	resp, err := f.apiRequest(ctx, "POST", "/machines", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var m flyMachine
	return &m, json.NewDecoder(resp.Body).Decode(&m)
}

// updateMachine updates a machine's config (image, init, guest) without
// destroying it. The machine must be stopped. Preserves env vars, metadata,
// and mounts from the existing config.
func (f *FlyRuntime) updateMachine(ctx context.Context, id string, cfg map[string]interface{}) error {
	body := map[string]interface{}{"config": cfg}
	resp, err := f.apiRequest(ctx, "POST", "/machines/"+id, body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// needsUpdate checks whether a machine's image or init command is outdated.
func (f *FlyRuntime) needsUpdate(m flyMachine) bool {
	if m.Config.Image != f.cfg.Image {
		return true
	}
	if len(m.Config.Init.Cmd) == 0 || m.Config.Init.Cmd[0] != gatewayInitCmd {
		return true
	}
	return false
}

func (f *FlyRuntime) startMachine(ctx context.Context, id string) error {
	resp, err := f.apiRequest(ctx, "POST", "/machines/"+id+"/start", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (f *FlyRuntime) stopMachine(ctx context.Context, id string) error {
	resp, err := f.apiRequest(ctx, "POST", "/machines/"+id+"/stop", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (f *FlyRuntime) destroyMachine(ctx context.Context, id string) error {
	resp, err := f.apiRequest(ctx, "DELETE", "/machines/"+id+"?force=true", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (f *FlyRuntime) waitForState(ctx context.Context, id, state string, timeout time.Duration) error {
	path := fmt.Sprintf("/machines/%s/wait?state=%s&timeout=%d", id, state, int(timeout.Seconds()))
	resp, err := f.apiRequest(ctx, "GET", path, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (f *FlyRuntime) listVolumes(ctx context.Context) ([]flyVolume, error) {
	resp, err := f.apiRequest(ctx, "GET", "/volumes", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var vols []flyVolume
	return vols, json.NewDecoder(resp.Body).Decode(&vols)
}

func (f *FlyRuntime) ensureVolume(ctx context.Context, name string) (string, error) {
	vols, err := f.listVolumes(ctx)
	if err != nil {
		return "", err
	}
	for _, v := range vols {
		if v.Name == name && v.Region == f.cfg.Region {
			return v.ID, nil
		}
	}

	slog.Info("[fly] creating volume", "name", name, "region", f.cfg.Region)
	body := map[string]interface{}{
		"name":    name,
		"region":  f.cfg.Region,
		"size_gb": 1,
	}
	resp, err := f.apiRequest(ctx, "POST", "/volumes", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var vol flyVolume
	if err := json.NewDecoder(resp.Body).Decode(&vol); err != nil {
		return "", err
	}
	return vol.ID, nil
}
