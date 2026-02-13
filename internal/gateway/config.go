// Package gateway manages per-user OpenClaw gateway containers.
package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// awareConfig is the JSON structure written to stateDir/.aware/aware.json.
type awareConfig struct {
	Gateway gatewayConfig `json:"gateway"`
	Agents  agentsConfig  `json:"agents"`
}

type gatewayConfig struct {
	Mode           string           `json:"mode"`
	Port           int              `json:"port"`
	Bind           string           `json:"bind"`
	Auth           gatewayAuth      `json:"auth"`
	TrustedProxies []string         `json:"trustedProxies"`
	ControlUI      controlUIConfig  `json:"controlUi"`
}

type gatewayAuth struct {
	Mode  string `json:"mode"`
	Token string `json:"token"`
}

type controlUIConfig struct {
	DangerouslyDisableDeviceAuth bool     `json:"dangerouslyDisableDeviceAuth"`
	AllowedOrigins               []string `json:"allowedOrigins"`
}

type agentsConfig struct {
	Defaults agentDefaults `json:"defaults"`
}

type agentDefaults struct {
	Workspace string `json:"workspace"`
}

// WriteAwareConfig writes the aware.json config into stateDir/.aware/.
// Creates the directory if it doesn't exist.
func WriteAwareConfig(stateDir string, userID, email string, port int, gatewayToken string) error {
	awareDir := filepath.Join(stateDir, ".aware")
	if err := os.MkdirAll(awareDir, 0o755); err != nil {
		return fmt.Errorf("creating .aware dir: %w", err)
	}

	cfg := awareConfig{
		Gateway: gatewayConfig{
			Mode: "local",
			Port: port,
			Bind: "loopback",
			Auth: gatewayAuth{
				Mode:  "token",
				Token: gatewayToken,
			},
			TrustedProxies: []string{"127.0.0.1", "::1"},
			ControlUI: controlUIConfig{
				DangerouslyDisableDeviceAuth: true,
				AllowedOrigins: []string{
					fmt.Sprintf("http://127.0.0.1:%d", port),
					fmt.Sprintf("http://localhost:%d", port),
				},
			},
		},
		Agents: agentsConfig{
			Defaults: agentDefaults{
				Workspace: "/data/workspace",
			},
		},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}

	configPath := filepath.Join(awareDir, "aware.json")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		return fmt.Errorf("writing aware.json: %w", err)
	}

	return nil
}

// ReadModelEnv reads model API keys from stateDir/.aware/model-keys.env.
// Returns a map of env var name → value. Returns an empty map if the file
// doesn't exist.
func ReadModelEnv(stateDir string) (map[string]string, error) {
	envPath := filepath.Join(stateDir, ".aware", "model-keys.env")
	f, err := os.Open(envPath)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("opening model-keys.env: %w", err)
	}
	defer f.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq == -1 {
			continue
		}
		result[line[:eq]] = line[eq+1:]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading model-keys.env: %w", err)
	}

	return result, nil
}
