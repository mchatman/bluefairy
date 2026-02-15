package tenant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// Client manages tenant instances via the tenant-orchestrator API.
type Client struct {
	orchestratorURL string
	httpClient      *http.Client
	mu              sync.RWMutex
	instances       map[string]*Instance // userID -> instance info
}

// Instance represents a tenant instance.
type Instance struct {
	Name     string
	Endpoint string
	Token    string
}

// NewClient creates a new tenant orchestrator client.
func NewClient() *Client {
	orchestratorURL := os.Getenv("TENANT_ORCHESTRATOR_URL")
	if orchestratorURL == "" {
		orchestratorURL = "http://localhost:8081"
	}

	return &Client{
		orchestratorURL: orchestratorURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		instances: make(map[string]*Instance),
	}
}

// GetOrCreateInstance gets an existing instance or creates a new one.
// It always tries a GET first to avoid creating duplicates on retries.
func (c *Client) GetOrCreateInstance(ctx context.Context, userID string, token string) (*Instance, error) {
	// Check cache first
	c.mu.RLock()
	if inst, ok := c.instances[userID]; ok {
		c.mu.RUnlock()
		return inst, nil
	}
	c.mu.RUnlock()

	// Try GET first — if the instance already exists, use it
	inst, err := c.GetInstanceFromOrchestrator(ctx, userID)
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

	var result struct {
		Endpoint     string `json:"endpoint"`
		Status       string `json:"status"`
		GatewayToken string `json:"gateway_token"`
	}
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
		Endpoint: fmt.Sprintf("https://%s.wareit.ai", result.Endpoint),
		Token:    instToken,
	}

	// Cache it
	c.mu.Lock()
	c.instances[userID] = inst
	c.mu.Unlock()

	return inst, nil
}

// GetInstanceFromOrchestrator looks up an instance via the tenant-orchestrator API.
func (c *Client) GetInstanceFromOrchestrator(ctx context.Context, userID string) (*Instance, error) {
	// Check cache first
	c.mu.RLock()
	if inst, ok := c.instances[userID]; ok {
		c.mu.RUnlock()
		return inst, nil
	}
	c.mu.RUnlock()

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

	var result struct {
		Endpoint     string `json:"endpoint"`
		Status       string `json:"status"`
		GatewayToken string `json:"gateway_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	inst := &Instance{
		Name:     result.Endpoint,
		Endpoint: fmt.Sprintf("https://%s.wareit.ai", result.Endpoint),
		Token:    result.GatewayToken,
	}

	// Cache it
	c.mu.Lock()
	c.instances[userID] = inst
	c.mu.Unlock()

	return inst, nil
}