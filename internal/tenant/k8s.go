package tenant

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// K8sClient looks up tenant instances directly from the Kubernetes API
// by reading OpenClawInstance custom resources. This avoids the need
// for a separate orchestrator HTTP API.
//
// It works by querying the k8s API server for OpenClawInstance CRs
// in the configured namespace, matching on the 'tenant' label.
type K8sClient struct {
	apiServer          string
	token              string
	namespace          string
	tenantBaseURL      string
	tenantHostTemplate string
	httpClient         *http.Client
	mu                 sync.RWMutex
	cache              map[string]*Instance // userID -> instance
}

// openClawInstance represents the relevant fields of the OpenClawInstance CR.
type openClawInstance struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		Env []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"env"`
	} `json:"spec"`
	Status struct {
		Phase   string `json:"phase"`
		Gateway string `json:"gateway"`
	} `json:"status"`
}

type openClawInstanceList struct {
	Items []openClawInstance `json:"items"`
}

// NewK8sClient creates a tenant client that reads from the Kubernetes API.
// Uses in-cluster service account credentials automatically.
func NewK8sClient() (*K8sClient, error) {
	namespace := os.Getenv("TENANT_NAMESPACE")
	if namespace == "" {
		namespace = "tenants"
	}

	tenantBaseURL := os.Getenv("TENANT_BASE_URL")
	if tenantBaseURL == "" {
		tenantBaseURL = "http://tenant-{name}.tenants.svc.cluster.local:18789"
	}

	tenantHostTemplate := os.Getenv("TENANT_HOST_TEMPLATE")

	// In-cluster config
	apiServer := "https://kubernetes.default.svc"
	tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("reading service account token: %w (are you running in-cluster?)", err)
	}

	// Load the cluster CA certificate for TLS verification
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("reading cluster CA: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse cluster CA certificate")
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}

	client := &K8sClient{
		apiServer:    apiServer,
		token:        strings.TrimSpace(string(tokenBytes)),
		namespace:    namespace,
		tenantBaseURL:      tenantBaseURL,
		tenantHostTemplate: tenantHostTemplate,
		httpClient:   httpClient,
		cache:        make(map[string]*Instance),
	}

	// Pre-populate cache
	if err := client.refreshCache(context.Background()); err != nil {
		// Log but don't fail — cache will be populated lazily
		fmt.Printf("[k8s-tenant] initial cache refresh failed: %v\n", err)
	}

	// Background cache refresh every 30 seconds
	go client.backgroundRefresh()

	return client, nil
}

func (c *K8sClient) buildEndpoint(name string) string {
	return strings.ReplaceAll(c.tenantBaseURL, "{name}", strings.TrimPrefix(name, "tenant-"))
}

func (c *K8sClient) buildHost(name string) string {
	if c.tenantHostTemplate == "" {
		return ""
	}
	return strings.ReplaceAll(c.tenantHostTemplate, "{name}", strings.TrimPrefix(name, "tenant-"))
}

// GetInstanceFromOrchestrator implements the same interface as Client.
func (c *K8sClient) GetInstanceFromOrchestrator(ctx context.Context, userID string) (*Instance, error) {
	// Check cache
	c.mu.RLock()
	if inst, ok := c.cache[userID]; ok {
		c.mu.RUnlock()
		return inst, nil
	}
	c.mu.RUnlock()

	// Cache miss — do a targeted lookup
	inst, err := c.lookupByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if inst == nil {
		return nil, nil
	}

	c.mu.Lock()
	c.cache[userID] = inst
	c.mu.Unlock()

	return inst, nil
}

// GetOrCreateInstance looks up an existing instance. Creation is handled
// by the openclaw-operator via CRDs, not by this client.
func (c *K8sClient) GetOrCreateInstance(ctx context.Context, userID string, token string) (*Instance, error) {
	return c.GetInstanceFromOrchestrator(ctx, userID)
}

func (c *K8sClient) lookupByUserID(ctx context.Context, userID string) (*Instance, error) {
	// Query by label selector: tenant={userID}
	// Use short user ID prefix for label matching (labels use first 8 chars)
	url := fmt.Sprintf(
		"%s/apis/openclaw.rocks/v1alpha1/namespaces/%s/openclawinstances?labelSelector=tenant=%s",
		c.apiServer, c.namespace, userID,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("k8s API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("k8s API error %d: %s", resp.StatusCode, body)
	}

	var list openClawInstanceList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}

	if len(list.Items) == 0 {
		return nil, nil
	}

	return c.crToInstance(&list.Items[0]), nil
}

func (c *K8sClient) crToInstance(cr *openClawInstance) *Instance {
	// Extract gateway token from env vars
	var gatewayToken string
	for _, env := range cr.Spec.Env {
		if env.Name == "OPENCLAW_GATEWAY_TOKEN" {
			gatewayToken = env.Value
			break
		}
	}

	name := cr.Metadata.Name

	return &Instance{
		Name:     name,
		Endpoint: c.buildEndpoint(name),
		Host:     c.buildHost(name),
		Token:    gatewayToken,
	}
}

func (c *K8sClient) refreshCache(ctx context.Context) error {
	url := fmt.Sprintf(
		"%s/apis/openclaw.rocks/v1alpha1/namespaces/%s/openclawinstances",
		c.apiServer, c.namespace,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("k8s API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("k8s API error %d: %s", resp.StatusCode, body)
	}

	var list openClawInstanceList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return err
	}

	newCache := make(map[string]*Instance, len(list.Items))
	for i := range list.Items {
		cr := &list.Items[i]
		if cr.Status.Phase != "Running" {
			continue
		}
		userID := cr.Metadata.Labels["tenant"]
		if userID == "" {
			continue
		}
		newCache[userID] = c.crToInstance(cr)
	}

	c.mu.Lock()
	c.cache = newCache
	c.mu.Unlock()

	return nil
}

func (c *K8sClient) backgroundRefresh() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := c.refreshCache(context.Background()); err != nil {
			fmt.Printf("[k8s-tenant] cache refresh failed: %v\n", err)
		}
	}
}
