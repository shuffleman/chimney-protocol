// Package config provides configuration loading and validation for Chimney.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// RelayConfig is the configuration for the relay server.
type RelayConfig struct {
	// Listen address (e.g., ":443" or "0.0.0.0:443")
	ListenAddr string `yaml:"listen_addr"`

	// PSK is the pre-shared key (hex-encoded string).
	// Optional if Users or UserIDs is set.
	PSK string `yaml:"psk,omitempty"`

	// Users maps user identifiers to their hex-encoded PSKs.
	// Optional if PSK or UserIDs is set.
	Users map[string]string `yaml:"users,omitempty"`

	// UserIDs is a list of user identifiers (e.g. UUIDs) for multi-user mode.
	// Each user's PSK is derived as SHA256(userID). This is the recommended field.
	// Optional if PSK or Users is set.
	UserIDs []string `yaml:"user_ids,omitempty"`

	// TagLen is the authentication tag length in bytes (8-16).
	TagLen int `yaml:"tag_len"`

	// IntentFile is the path to the intent whitelist YAML file.
	IntentFile string `yaml:"intent_file"`

	// EnforceFile is the path to the enforce CIDR YAML file.
	EnforceFile string `yaml:"enforce_file"`

	// CloudRegion is the cloud region for CIDR validation (e.g., "us-east-1").
	CloudRegion string `yaml:"cloud_region"`

	// DefaultBackend is the fallback backend address for non-authenticated traffic.
	// Format: "host:port". If empty, connections are closed naturally on failure.
	DefaultBackend string `yaml:"default_backend,omitempty"`

	// HandshakeTimeout is the maximum time for TLS handshake relay.
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`

	// AuthReadTimeout is the timeout for reading the auth record.
	AuthReadTimeout time.Duration `yaml:"auth_read_timeout"`

	// EnableProfiling enables traffic profiling and pacing.
	EnableProfiling bool `yaml:"enable_profiling"`

	// ProfileDir is the directory containing site profile JSON files.
	ProfileDir string `yaml:"profile_dir,omitempty"`

	// CIDRRefreshInterval is how often to refresh CIDR lists from cloud providers.
	CIDRRefreshInterval time.Duration `yaml:"cidr_refresh_interval,omitempty"`

	// LogLevel is the logging level (debug, info, warn, error).
	LogLevel string `yaml:"log_level"`

	// MetricsAddr is the address for Prometheus metrics endpoint.
	// If empty, metrics are disabled.
	MetricsAddr string `yaml:"metrics_addr,omitempty"`
}

// ClientConfig is the configuration for the client.
type ClientConfig struct {
	// RelayAddr is the relay server address (host:port).
	RelayAddr string `yaml:"relay_addr"`

	// SNI is the Server Name Indicator to use (must be in relay's whitelist).
	SNI string `yaml:"sni"`

	// DestAddr is the final destination address (host:port).
	DestAddr string `yaml:"dest_addr"`

	// PSK is the pre-shared key (hex-encoded string).
	// Optional if UserID is set.
	PSK string `yaml:"psk,omitempty"`

	// UserID is the user identifier (e.g. UUID) for multi-user relay.
	// If set, PSK is derived as SHA256(UserID) when PSK is empty.
	UserID string `yaml:"user_id,omitempty"`

	// TagLen is the authentication tag length.
	TagLen int `yaml:"tag_len"`

	// ListenAddr is the local SOCKS5 proxy address.
	ListenAddr string `yaml:"listen_addr"`

	// UTlsFingerprint is the uTLS fingerprint to use (e.g., "chrome", "firefox", "safari").
	UTlsFingerprint string `yaml:"utls_fingerprint,omitempty"`

	// ConnectTimeout is the timeout for relay connections.
	ConnectTimeout time.Duration `yaml:"connect_timeout"`

	// HandshakeTimeout is the timeout for TLS handshake.
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`
}

// DefaultRelayConfig returns a default relay configuration.
func DefaultRelayConfig() *RelayConfig {
	return &RelayConfig{
		ListenAddr:          ":443",
		TagLen:              16,
		IntentFile:          "config/intent.yaml",
		EnforceFile:         "config/enforce.yaml",
		HandshakeTimeout:    10 * time.Second,
		AuthReadTimeout:     5 * time.Second,
		EnableProfiling:     true,
		CIDRRefreshInterval: 24 * time.Hour,
		LogLevel:            "info",
	}
}

// DefaultClientConfig returns a default client configuration.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		TagLen:           16,
		ListenAddr:       "127.0.0.1:1080",
		UTlsFingerprint:  "chrome",
		ConnectTimeout:   10 * time.Second,
		HandshakeTimeout: 10 * time.Second,
	}
}

// Validate validates the relay configuration.
func (c *RelayConfig) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("config: listen_addr is required")
	}
	if c.PSK == "" && len(c.Users) == 0 && len(c.UserIDs) == 0 {
		return fmt.Errorf("config: one of psk, users, or user_ids is required")
	}
	if c.TagLen < 8 || c.TagLen > 32 {
		return fmt.Errorf("config: tag_len must be between 8 and 32")
	}
	if c.CloudRegion == "" {
		return fmt.Errorf("config: cloud_region is required (e.g., us-east-1)")
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 10 * time.Second
	}
	if c.AuthReadTimeout == 0 {
		c.AuthReadTimeout = 5 * time.Second
	}
	return nil
}

// Validate validates the client configuration.
func (c *ClientConfig) Validate() error {
	if c.RelayAddr == "" {
		return fmt.Errorf("config: relay_addr is required")
	}
	if c.SNI == "" {
		return fmt.Errorf("config: sni is required")
	}
	if c.PSK == "" {
		if c.UserID == "" {
			return fmt.Errorf("config: psk or user_id is required")
		}
	}
	if c.TagLen < 8 || c.TagLen > 32 {
		return fmt.Errorf("config: tag_len must be between 8 and 32")
	}
	return nil
}

// LoadRelayConfig loads relay configuration from a YAML file.
func LoadRelayConfig(path string) (*RelayConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read relay config: %w", err)
	}

	config := DefaultRelayConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("config: parse relay config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// LoadClientConfig loads client configuration from a YAML file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read client config: %w", err)
	}

	config := DefaultClientConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("config: parse client config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// SaveRelayConfig saves relay configuration to a YAML file.
func SaveRelayConfig(path string, config *RelayConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("config: marshal relay config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("config: write relay config: %w", err)
	}

	return nil
}

// SaveClientConfig saves client configuration to a YAML file.
func SaveClientConfig(path string, config *ClientConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("config: marshal client config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("config: write client config: %w", err)
	}

	return nil
}
