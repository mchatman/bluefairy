// Package tenant provides a client for looking up and provisioning per-user
// tenant instances via the tenant-orchestrator HTTP API.
package tenant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const cacheTTL = 2 * time.Minute

// cachedInstance pairs an Instance with its cache insertion time.
type cachedInstance struct {
	inst      *Instance
	fetchedAt time.Time
}

// Instance represents a running tenant workspace.
type Instance struct {
	// Name is the instance identifier returned by the orchestrator (e.g. "tenant-1c9de7b5").
	Name string

	// Endpoint is the URL used to connect to the tenant
	// (e.g. "http://tenant-1c9de7b5.wareit.ai").
	Endpoint string

	// Token is the gateway authentication token passed to the tenant instance
	// as a query parameter or header.
	Token string
}

// orchestratorResponse is the JSON envelope returned by the tenant-orchestrator
// API for instance operations.
type orchestratorResponse struct {
	Endpoint     string `json:"endpoint"`
	Status       string `json:"status"`
	GatewayToken string `json:"gateway_token"`
}

// Client manages tenant instances via the tenant-orchestrator API.
type Client struct {
	orchestratorURL string
	tenantBaseURL   string // e.g. "http://{name}.wareit.ai"
	httpClient      *http.Client
	mu              sync.RWMutex
	cache           map[string]*cachedInstance // userID -> instance + timestamp
}

// NewClient creates a new tenant orchestrator client.
// orchestratorURL is the base URL of the tenant-orchestrator API.
// tenantBaseURL is the URL template for tenant endpoints; the literal
// string "{name}" is replaced with the instance name.
func NewClient(orchestratorURL, tenantBaseURL string) *Client {
	return &Client{
		orchestratorURL: orchestratorURL,
		tenantBaseURL:   tenantBaseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache: make(map[string]*cachedInstance),
	}
}

// buildEndpoint constructs the tenant endpoint URL from the base URL template
// and the instance name returned by the orchestrator.
func (c *Client) buildEndpoint(name string) string {
	return strings.ReplaceAll(c.tenantBaseURL, "{name}", name)
}

// CreateInstance provisions a new instance for the user.
// It calls GetInstance first to avoid creating duplicates on retries.
func (c *Client) CreateInstance(ctx context.Context, userID string, token string) (*Instance, error) {
	// Try GET first — if the instance already exists, use it
	inst, err := c.GetInstance(ctx, userID)
	if err == nil && inst != nil {
		return inst, nil
	}

	// Instance doesn't exist yet — create it
	apiURL := fmt.Sprintf("%s/tenants/%s/instance", c.orchestratorURL, userID)

	reqBody := map[string]string{
		"gateway_token": token,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling tenant-orchestrator: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("orchestrator error %d: %s", resp.StatusCode, respBody)
	}

	var result orchestratorResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Use the token returned by the orchestrator if available,
	// otherwise fall back to the one we sent.
	instToken := result.GatewayToken
	if instToken == "" {
		instToken = token
	}

	inst = &Instance{
		Name:     result.Endpoint,
		Endpoint: c.buildEndpoint(result.Endpoint),
		Token:    instToken,
	}

	c.cacheSet(userID, inst)
	return inst, nil
}

// GetInstance looks up an instance via the tenant-orchestrator API.
func (c *Client) GetInstance(ctx context.Context, userID string) (*Instance, error) {
	if inst := c.cacheGet(userID); inst != nil {
		return inst, nil
	}

	url := fmt.Sprintf("%s/tenants/%s/instance", c.orchestratorURL, userID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling tenant-orchestrator: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("orchestrator error %d: %s", resp.StatusCode, body)
	}

	var result orchestratorResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	inst := &Instance{
		Name:     result.Endpoint,
		Endpoint: c.buildEndpoint(result.Endpoint),
		Token:    result.GatewayToken,
	}

	c.cacheSet(userID, inst)
	return inst, nil
}

func (c *Client) cacheGet(userID string) *Instance {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, ok := c.cache[userID]; ok && time.Since(entry.fetchedAt) < cacheTTL {
		return entry.inst
	}
	return nil
}

func (c *Client) cacheSet(userID string, inst *Instance) {
	c.mu.Lock()
	c.cache[userID] = &cachedInstance{inst: inst, fetchedAt: time.Now()}
	c.mu.Unlock()
}