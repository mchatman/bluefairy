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

const cacheTTL = 2 * time.Minute

// cachedInstance pairs an Instance with its cache insertion time.
type cachedInstance struct {
	inst      *Instance
	fetchedAt time.Time
}

// Client manages tenant instances via the tenant-orchestrator API.
type Client struct {
	orchestratorURL    string
	tenantBaseURL      string // e.g. "https://{name}.wareit.ai" or "http://24.199.73.199"
	tenantHostTemplate string // e.g. "{name}.internal.wareit.ai" — for Host header routing when using IP-based base URL
	httpClient         *http.Client
	mu                 sync.RWMutex
	cache              map[string]*cachedInstance // userID -> instance + timestamp
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
		cache: make(map[string]*cachedInstance),
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