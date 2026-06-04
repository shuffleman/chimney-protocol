// Package config 提供 Chimney 的配置加载和验证。
package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// RelayConfig 是中继服务器的配置。
type RelayConfig struct {
	// 监听地址（例如 ":443" 或 "0.0.0.0:443"）
	ListenAddr string `yaml:"listen_addr"`

	// PSK 是预共享密钥（hex 编码字符串）。
	// 如果设置了 Users 或 UserIDs 则可选。
	PSK string `yaml:"psk,omitempty"`

	// Users 将用户标识符映射到其 hex 编码的 PSK。
	// 如果设置了 PSK 或 UserIDs 则可选。
	Users map[string]string `yaml:"users,omitempty"`

	// UserIDs 是多用户模式的用户标识符列表（例如 UUID）。
	// 每个用户的 PSK 派生为 SHA256(userID)。这是推荐字段。
	// 如果设置了 PSK 或 Users 则可选。
	UserIDs []string `yaml:"user_ids,omitempty"`

	// TagLen 是认证标签长度（字节，8-16）。
	TagLen int `yaml:"tag_len"`

	// IntentFile 是意图白名单 YAML 文件的路径。
	IntentFile string `yaml:"intent_file"`

	// EnforceFile 是强制 CIDR YAML 文件的路径。
	EnforceFile string `yaml:"enforce_file"`

	// CloudRegion 是 CIDR 验证的云区域（例如 "us-east-1"）。
	CloudRegion string `yaml:"cloud_region"`

	// DefaultBackend 是未认证流量的回退后端地址。
	// 格式："host:port"。如果为空，失败时自然关闭连接。
	DefaultBackend string `yaml:"default_backend,omitempty"`

	// HandshakeTimeout 是 TLS 握手中继的最大时间。
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`

	// AuthReadTimeout 是读取认证记录的超时时间。
	AuthReadTimeout time.Duration `yaml:"auth_read_timeout"`

	// EnableProfiling 启用流量分析和节奏控制。
	EnableProfiling bool `yaml:"enable_profiling"`

	// ProfileDir 是包含站点 Profile JSON 文件的目录。
	ProfileDir string `yaml:"profile_dir,omitempty"`

	// CIDRRefreshInterval 是从云服务商刷新 CIDR 列表的频率。
	CIDRRefreshInterval time.Duration `yaml:"cidr_refresh_interval,omitempty"`

	// LogLevel 是日志级别（debug, info, warn, error）。
	LogLevel string `yaml:"log_level"`

	// MetricsAddr 是 Prometheus 指标端点的地址。
	// 如果为空，则禁用指标。
	MetricsAddr string `yaml:"metrics_addr,omitempty"`

	// MetricsToken 保护管理端点。如果为空，管理端点
	// 仅限 loopback 客户端访问。
	MetricsToken string `yaml:"metrics_token,omitempty"`

	// ConnectAllowCIDRs 限制已认证 CONNECT 目标在这些 CIDR
	// 范围内。为空表示不做白名单限制。
	ConnectAllowCIDRs []string `yaml:"connect_allow_cidrs,omitempty"`

	// ConnectDenyCIDRs 拒绝已认证 CONNECT 目标在这些 CIDR
	// 范围内。拒绝规则优先于允许规则。
	ConnectDenyCIDRs []string `yaml:"connect_deny_cidrs,omitempty"`

	// ConnectDenyPrivate 在认证后拒绝私有、loopback、链路本地、
	// 多播和未指定 CONNECT 目标。
	ConnectDenyPrivate bool `yaml:"connect_deny_private,omitempty"`
}

// ClientConfig 是客户端的配置。
type ClientConfig struct {
	// RelayAddr 是中继服务器地址（host:port）。
	RelayAddr string `yaml:"relay_addr"`

	// SNI 是要使用的服务器名称指示（必须在中继的白名单中）。
	SNI string `yaml:"sni"`

	// DestAddr 是最终目标地址（host:port）。
	DestAddr string `yaml:"dest_addr"`

	// PSK 是预共享密钥（hex 编码字符串）。
	// 如果设置了 UserID 则可选。
	PSK string `yaml:"psk,omitempty"`

	// UserID 是多用户中继的用户标识符（例如 UUID）。
	// 如果设置了且 PSK 为空，则 PSK 派生为 SHA256(UserID)。
	UserID string `yaml:"user_id,omitempty"`

	// TagLen 是认证标签长度。
	TagLen int `yaml:"tag_len"`

	// ListenAddr 是本地 SOCKS5 代理地址。
	ListenAddr string `yaml:"listen_addr"`

	// UTlsFingerprint 是要使用的 uTLS 指纹（例如 "chrome", "firefox", "safari"）。
	UTlsFingerprint string `yaml:"utls_fingerprint,omitempty"`

	// ConnectTimeout 是中继连接的超时时间。
	ConnectTimeout time.Duration `yaml:"connect_timeout"`

	// HandshakeTimeout 是 TLS 握手的超时时间。
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`
}

// DefaultRelayConfig 返回默认的中继配置。
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

// DefaultClientConfig 返回默认的客户端配置。
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		TagLen:           16,
		ListenAddr:       "127.0.0.1:1080",
		UTlsFingerprint:  "chrome",
		ConnectTimeout:   10 * time.Second,
		HandshakeTimeout: 10 * time.Second,
	}
}

// Validate 验证中继配置。
func (c *RelayConfig) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("config: listen_addr is required")
	}
	if c.PSK == "" && len(c.Users) == 0 && len(c.UserIDs) == 0 {
		return fmt.Errorf("config: one of psk, users, or user_ids is required")
	}
	if c.PSK != "" {
		if err := validateHexPSK("psk", c.PSK); err != nil {
			return err
		}
	}
	for userID, psk := range c.Users {
		if err := validateHexPSK("users."+userID, psk); err != nil {
			return err
		}
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
	if err := validateCIDRs("connect_allow_cidrs", c.ConnectAllowCIDRs); err != nil {
		return err
	}
	if err := validateCIDRs("connect_deny_cidrs", c.ConnectDenyCIDRs); err != nil {
		return err
	}
	return nil
}

// Validate 验证客户端配置。
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
	} else if err := validateHexPSK("psk", c.PSK); err != nil {
		return err
	}
	if c.TagLen < 8 || c.TagLen > 32 {
		return fmt.Errorf("config: tag_len must be between 8 and 32")
	}
	return nil
}

func validateHexPSK(field, value string) error {
	psk, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("config: %s must be hex: %w", field, err)
	}
	if len(psk) != 32 {
		return fmt.Errorf("config: %s must decode to 32 bytes, got %d", field, len(psk))
	}
	return nil
}

func validateCIDRs(field string, cidrs []string) error {
	for _, cidr := range cidrs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("config: %s contains invalid CIDR %q: %w", field, cidr, err)
		}
	}
	return nil
}

// LoadRelayConfig 从 YAML 文件加载中继配置。
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

// LoadClientConfig 从 YAML 文件加载客户端配置。
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

// SaveRelayConfig 将中继配置保存到 YAML 文件。
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

// SaveClientConfig 将客户端配置保存到 YAML 文件。
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
