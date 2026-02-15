package tenant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Client manages tenant instances via the tenant-orchestrator API.
type Client struct {
	orchestratorURL   string
	tenantBaseURL     string // e.g. "https://{name}.wareit.ai" or "http://24.199.73.199"
	tenantHostTemplate string // e.g. "{name}.internal.wareit.ai" — for Host header routing when using IP-based base URL
	httpClient        *http.Client
	mu                sync.RWMutex
	instances         map[string]*Instance // userID -> instance info
}

// NewClient creates a new tenant orchestrator client.
// Set TENANT_BASE_URL to control how tenant endpoints are constructed.
// Examples:
//   - "https://{name}.wareit.ai"      — public DNS (default, insecure)
//   - "http://{name}.internal:18789"  — VPC-internal (recommended for DO)
//   - "http://10.0.0.{name}:18789"   — private IP pattern
//
// The literal string "{name}" is replaced with the instance name from the
// orchestrator response.
func NewClient() *Client {
	orchestratorURL := os.Getenv("TENANT_ORCHESTRATOR_URL")
	if orchestratorURL == "" {
		orchestratorURL = "http://localhost:8081"
	}

	tenantBaseURL := os.Getenv("TENANT_BASE_URL")
	if tenantBaseURL == "" {
		tenantBaseURL = "https://{name}.wareit.ai"
	}

	// TENANT_HOST_TEMPLATE is used when TENANT_BASE_URL points to a raw IP
	// (e.g. http://24.199.73.199) and nginx ingress needs a real hostname in
	// the Host header for routing. Example: "{name}.internal.wareit.ai"
	tenantHostTemplate := os.Getenv("TENANT_HOST_TEMPLATE")

	return &Client{
		orchestratorURL:    orchestratorURL,
		tenantBaseURL:      tenantBaseURL,
		tenantHostTemplate: tenantHostTemplate,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		instances: make(map[string]*Instance),
	}
}

// buildEndpoint constructs the tenant endpoint URL from the base URL template
// and the instance name returned by the orchestrator.
func (c *Client) buildEndpoint(name string) string {
	return strings.ReplaceAll(c.tenantBaseURL, "{name}", name)
}

// buildHost returns the hostname for the Host header, or empty if no template.
func (c *Client) buildHost(name string) string {
	if c.tenantHostTemplate == "" {
		return ""
	}
	return strings.ReplaceAll(c.tenantHostTemplate, "{name}", name)
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
		Endpoint: c.buildEndpoint(result.Endpoint),
		Host:     c.buildHost(result.Endpoint),
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
		Endpoint: c.buildEndpoint(result.Endpoint),
		Host:     c.buildHost(result.Endpoint),
		Token:    result.GatewayToken,
	}

	// Cache it
	c.mu.Lock()
	c.instances[userID] = inst
	c.mu.Unlock()

	return inst, nil
}