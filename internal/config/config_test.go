package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultRelayConfig(t *testing.T) {
	c := DefaultRelayConfig()
	if c == nil {
		t.Fatal("DefaultRelayConfig returned nil")
	}
	if c.ListenAddr != ":443" {
		t.Errorf("ListenAddr = %q, want %q", c.ListenAddr, ":443")
	}
	if c.TagLen != 16 {
		t.Errorf("TagLen = %d, want 16", c.TagLen)
	}
	if c.HandshakeTimeout != 10*time.Second {
		t.Errorf("HandshakeTimeout = %v, want 10s", c.HandshakeTimeout)
	}
	if c.AuthReadTimeout != 5*time.Second {
		t.Errorf("AuthReadTimeout = %v, want 5s", c.AuthReadTimeout)
	}
	if c.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", c.LogLevel, "info")
	}
}

func TestDefaultClientConfig(t *testing.T) {
	c := DefaultClientConfig()
	if c == nil {
		t.Fatal("DefaultClientConfig returned nil")
	}
	if c.TagLen != 16 {
		t.Errorf("TagLen = %d, want 16", c.TagLen)
	}
	if c.ListenAddr != "127.0.0.1:1080" {
		t.Errorf("ListenAddr = %q, want %q", c.ListenAddr, "127.0.0.1:1080")
	}
	if c.UTlsFingerprint != "chrome" {
		t.Errorf("UTlsFingerprint = %q, want %q", c.UTlsFingerprint, "chrome")
	}
}

func TestRelayConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *RelayConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &RelayConfig{
				ListenAddr:  ":443",
				PSK:         "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
				TagLen:      16,
				CloudRegion: "us-east-1",
			},
			wantErr: false,
		},
		{
			name: "valid CONNECT ACL config",
			config: &RelayConfig{
				ListenAddr:         ":443",
				PSK:                "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
				TagLen:             16,
				CloudRegion:        "us-east-1",
				ConnectAllowCIDRs:  []string{"203.0.113.0/24"},
				ConnectDenyCIDRs:   []string{"203.0.113.10/32"},
				ConnectDenyPrivate: true,
			},
			wantErr: false,
		},
		{
			name: "missing listen addr",
			config: &RelayConfig{
				PSK:         "deadbeef",
				TagLen:      16,
				CloudRegion: "us-east-1",
			},
			wantErr: true,
		},
		{
			name: "missing PSK",
			config: &RelayConfig{
				ListenAddr:  ":443",
				TagLen:      16,
				CloudRegion: "us-east-1",
			},
			wantErr: true,
		},
		{
			name: "tag len too small",
			config: &RelayConfig{
				ListenAddr:  ":443",
				PSK:         "deadbeef",
				TagLen:      4,
				CloudRegion: "us-east-1",
			},
			wantErr: true,
		},
		{
			name: "tag len too large",
			config: &RelayConfig{
				ListenAddr:  ":443",
				PSK:         "deadbeef",
				TagLen:      40,
				CloudRegion: "us-east-1",
			},
			wantErr: true,
		},
		{
			name: "missing cloud region",
			config: &RelayConfig{
				ListenAddr: ":443",
				PSK:        "deadbeef",
				TagLen:     16,
			},
			wantErr: true,
		},
		{
			name: "invalid CONNECT allow CIDR",
			config: &RelayConfig{
				ListenAddr:        ":443",
				PSK:               "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
				TagLen:            16,
				CloudRegion:       "us-east-1",
				ConnectAllowCIDRs: []string{"not-a-cidr"},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestClientConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *ClientConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &ClientConfig{
				RelayAddr: "relay.example.com:443",
				SNI:       "real-site.example.com",
				PSK:       "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
				TagLen:    16,
			},
			wantErr: false,
		},
		{
			name: "missing relay addr",
			config: &ClientConfig{
				SNI:    "example.com",
				PSK:    "deadbeef",
				TagLen: 16,
			},
			wantErr: true,
		},
		{
			name: "missing SNI",
			config: &ClientConfig{
				RelayAddr: "relay.example.com:443",
				PSK:       "deadbeef",
				TagLen:    16,
			},
			wantErr: true,
		},
		{
			name: "missing PSK",
			config: &ClientConfig{
				RelayAddr: "relay.example.com:443",
				SNI:       "example.com",
				TagLen:    16,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestLoadRelayConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "relay.yaml")

	configContent := `
listen_addr: ":8443"
psk: "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
tag_len: 16
cloud_region: "eu-west-1"
handshake_timeout: 15s
auth_read_timeout: 10s
log_level: "debug"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	config, err := LoadRelayConfig(configPath)
	if err != nil {
		t.Fatalf("LoadRelayConfig failed: %v", err)
	}

	if config.ListenAddr != ":8443" {
		t.Errorf("ListenAddr = %q, want %q", config.ListenAddr, ":8443")
	}
	if config.CloudRegion != "eu-west-1" {
		t.Errorf("CloudRegion = %q, want %q", config.CloudRegion, "eu-west-1")
	}
	if config.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", config.LogLevel, "debug")
	}
}

func TestLoadRelayConfig_NotFound(t *testing.T) {
	_, err := LoadRelayConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

func TestSaveRelayConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "relay-out.yaml")

	config := &RelayConfig{
		ListenAddr:       ":9443",
		PSK:              "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
		TagLen:           16,
		CloudRegion:      "ap-southeast-1",
		HandshakeTimeout: 10 * time.Second,
		AuthReadTimeout:  5 * time.Second,
		LogLevel:         "info",
	}

	if err := SaveRelayConfig(configPath, config); err != nil {
		t.Fatalf("SaveRelayConfig failed: %v", err)
	}

	// 验证文件存在且可读
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read saved config: %v", err)
	}
	if len(data) == 0 {
		t.Error("Saved config is empty")
	}

	// 重新加载
	loaded, err := LoadRelayConfig(configPath)
	if err != nil {
		t.Fatalf("LoadRelayConfig on saved file failed: %v", err)
	}
	if loaded.ListenAddr != config.ListenAddr {
		t.Errorf("Round-trip ListenAddr = %q, want %q", loaded.ListenAddr, config.ListenAddr)
	}
}

func TestLoadClientConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "client.yaml")

	configContent := `
relay_addr: "relay.example.com:443"
sni: "real-site.example.com"
psk: "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
tag_len: 16
listen_addr: "127.0.0.1:2080"
utls_fingerprint: "firefox"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	config, err := LoadClientConfig(configPath)
	if err != nil {
		t.Fatalf("LoadClientConfig failed: %v", err)
	}

	if config.RelayAddr != "relay.example.com:443" {
		t.Errorf("RelayAddr = %q, want %q", config.RelayAddr, "relay.example.com:443")
	}
	if config.SNI != "real-site.example.com" {
		t.Errorf("SNI = %q, want %q", config.SNI, "real-site.example.com")
	}
	if config.ListenAddr != "127.0.0.1:2080" {
		t.Errorf("ListenAddr = %q, want %q", config.ListenAddr, "127.0.0.1:2080")
	}
	if config.UTlsFingerprint != "firefox" {
		t.Errorf("UTlsFingerprint = %q, want %q", config.UTlsFingerprint, "firefox")
	}
}

func TestSaveClientConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "client-out.yaml")

	config := &ClientConfig{
		RelayAddr:  "relay.test:443",
		SNI:        "site.test",
		PSK:        "testpsk",
		TagLen:     16,
		ListenAddr: "127.0.0.1:3080",
	}

	if err := SaveClientConfig(configPath, config); err != nil {
		t.Fatalf("SaveClientConfig failed: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read saved config: %v", err)
	}
	if len(data) == 0 {
		t.Error("Saved config is empty")
	}
}

func TestConfig_DefaultTimeouts(t *testing.T) {
	// 当超时时间为零时，验证应设置默认值
	c := &RelayConfig{
		ListenAddr:  ":443",
		PSK:         "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
		TagLen:      16,
		CloudRegion: "us-east-1",
	}

	// 验证前，超时时间为零
	if c.HandshakeTimeout != 0 {
		t.Error("HandshakeTimeout should be zero before validation")
	}

	// 验证后，设置默认值
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if c.HandshakeTimeout != 10*time.Second {
		t.Errorf("HandshakeTimeout after validation = %v, want 10s", c.HandshakeTimeout)
	}
	if c.AuthReadTimeout != 5*time.Second {
		t.Errorf("AuthReadTimeout after validation = %v, want 5s", c.AuthReadTimeout)
	}
}
