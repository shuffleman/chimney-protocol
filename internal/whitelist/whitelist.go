// Package whitelist 实现双层白名单系统（第二部分 §10）：
//
// 意图层（配置）：允许的站点名称列表（SNI 值）。
// 在此处写入错误条目只会导致该站点不可用——而非致命错误。
//
// 强制执法层（强制执法）：云提供商/区域 CIDR 地址段。
// 中继 MUST 仅连接到这些 CIDR 范围内的目标 IP。
// 这是安全关键层，确保中继的出站连接停留在与白名单站点相同的云区域内。
//
// B（白名单安全属性）成立当且仅当：
//   - 中继与白名单站点托管在同一云/区域
//   - 所有出站连接的目标 IP 都在该区域的 CIDR 地址段内
//
// 当审查者连接到中继 IP 时，中继转发到真实站点，
// 该站点返回其真实证书。审查者无法区分
// "中继即是真实站点"和"中继转发到真实站点"，因为
// 两者位于同一云区域。
package whitelist

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultIntentFile 是意图层白名单的默认路径。
	DefaultIntentFile = "config/intent.yaml"

	// DefaultEnforceFile 是强制执法层 CIDR 配置的默认路径。
	DefaultEnforceFile = "config/enforce.yaml"

	// DefaultRefreshInterval 是来自云提供商的 CIDR 列表的默认刷新间隔。
	DefaultRefreshInterval = 24 * time.Hour

	// AWSIPRangesURL 是 AWS IP 地址范围的 URL。
	AWSIPRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
)

var (
	// ErrSNIRejected 表示 SNI 不在意图白名单中。
	ErrSNIRejected = errors.New("whitelist: SNI not in intent whitelist")

	// ErrIPRejected 表示目标 IP 不在强制执法 CIDR 地址范围中。
	ErrIPRejected = errors.New("whitelist: destination IP not in enforce CIDR ranges")

	// ErrSiteNotFound 表示请求的站点不在白名单中。
	ErrSiteNotFound = errors.New("whitelist: site not found")
)

// IntentEntry 是意图层白名单中的单个条目。
type IntentEntry struct {
	// SNI 是服务器名称指示（TLS SNI）值。
	SNI string `yaml:"sni" json:"sni"`

	// Description 是可选的供人类阅读的描述。
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// SettingsSnapshot 包含从该站点捕获的 HTTP/2 SETTINGS。
	// 在运行时从校准数据填充。
	SettingsSnapshot map[string]interface{} `yaml:"settings_snapshot,omitempty" json:"settings_snapshot,omitempty"`

	// ProfileModel 包含该站点的流量特征模型。
	// 在运行时从校准数据填充。
	ProfileModel map[string]interface{} `yaml:"profile_model,omitempty" json:"profile_model,omitempty"`
}

// IntentLayer 是意图层白名单（站点名称）。
type IntentLayer struct {
	// 用于配置跟踪的版本号。
	Version int `yaml:"version" json:"version"`

	// Entries 将 SNI（小写）映射到其白名单条目。
	Entries map[string]IntentEntry `yaml:"entries" json:"entries"`

	// UpdatedAt 记录白名单最后修改的时间。
	UpdatedAt time.Time `yaml:"updated_at" json:"updated_at"`

	mu sync.RWMutex
}

// NewIntentLayer 创建一个空的意图层。
func NewIntentLayer() *IntentLayer {
	return &IntentLayer{
		Version: 1,
		Entries: make(map[string]IntentEntry),
	}
}

// LoadIntentFromYAML 从 YAML 文件加载意图层。
func LoadIntentFromYAML(path string) (*IntentLayer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("whitelist: failed to read intent file %s: %w", path, err)
	}
	return ParseIntentYAML(data)
}

// ParseIntentYAML 从字节数据解析意图 YAML 内容。
func ParseIntentYAML(data []byte) (*IntentLayer, error) {
	return parseIntentData(data, yaml.Unmarshal)
}

// ParseIntentJSON 从字节数据解析意图 JSON 内容。
func ParseIntentJSON(data []byte) (*IntentLayer, error) {
	return parseIntentData(data, json.Unmarshal)
}

// parseIntentData 使用给定的反序列化器解析意图数据。
func parseIntentData(data []byte, unmarshal func([]byte, interface{}) error) (*IntentLayer, error) {
	intent := NewIntentLayer()
	if err := unmarshal(data, intent); err != nil {
		return nil, fmt.Errorf("whitelist: failed to parse intent: %w", err)
	}
	var compact struct {
		Allow []string `yaml:"allow" json:"allow"`
	}
	if len(intent.Entries) == 0 {
		if err := unmarshal(data, &compact); err != nil {
			return nil, fmt.Errorf("whitelist: failed to parse intent allow list: %w", err)
		}
		for _, sni := range compact.Allow {
			sni = strings.ToLower(strings.TrimSpace(sni))
			if sni == "" {
				continue
			}
			intent.Entries[sni] = IntentEntry{SNI: sni}
		}
	}

	// 将 SNI 规范化为小写
	normalized := make(map[string]IntentEntry, len(intent.Entries))
	for sni, entry := range intent.Entries {
		entry.SNI = strings.ToLower(strings.TrimSpace(entry.SNI))
		normalized[strings.ToLower(strings.TrimSpace(sni))] = entry
	}
	intent.Entries = normalized
	intent.UpdatedAt = time.Now()

	return intent, nil
}

// SaveToYAML 将意图层保存到 YAML 文件。
func (il *IntentLayer) SaveToYAML(path string) error {
	il.mu.RLock()
	defer il.mu.RUnlock()

	data, err := yaml.Marshal(il)
	if err != nil {
		return fmt.Errorf("whitelist: failed to marshal intent YAML: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("whitelist: failed to write intent file: %w", err)
	}
	return nil
}

// Contains 检查 SNI 是否在意图白名单中。
func (il *IntentLayer) Contains(sni string) bool {
	il.mu.RLock()
	defer il.mu.RUnlock()

	sni = strings.ToLower(strings.TrimSpace(sni))
	_, ok := il.Entries[sni]
	return ok
}

// Get 返回指定 SNI 的白名单条目。
func (il *IntentLayer) Get(sni string) (IntentEntry, bool) {
	il.mu.RLock()
	defer il.mu.RUnlock()

	sni = strings.ToLower(strings.TrimSpace(sni))
	entry, ok := il.Entries[sni]
	return entry, ok
}

// Add 添加或更新白名单条目。
func (il *IntentLayer) Add(entry IntentEntry) {
	il.mu.Lock()
	defer il.mu.Unlock()

	sni := strings.ToLower(strings.TrimSpace(entry.SNI))
	entry.SNI = sni
	il.Entries[sni] = entry
	il.UpdatedAt = time.Now()
}

// Remove 从白名单中移除一个 SNI。
func (il *IntentLayer) Remove(sni string) {
	il.mu.Lock()
	defer il.mu.Unlock()

	sni = strings.ToLower(strings.TrimSpace(sni))
	delete(il.Entries, sni)
	il.UpdatedAt = time.Now()
}

// List 返回白名单中的所有 SNI。
func (il *IntentLayer) List() []string {
	il.mu.RLock()
	defer il.mu.RUnlock()

	snis := make([]string, 0, len(il.Entries))
	for sni := range il.Entries {
		snis = append(snis, sni)
	}
	return snis
}

// EnforceEntry 是强制执法层的 CIDR 地址段。
type EnforceEntry struct {
	// CIDR 是 IP CIDR 地址段（例如 AWS us-east-1 的 "52.0.0.0/8"）。
	CIDR string `yaml:"cidr" json:"cidr"`

	// Provider 是云提供商名称（例如 "aws"、"gcp"、"azure"）。
	Provider string `yaml:"provider" json:"provider"`

	// Region 是云区域（例如 "us-east-1"）。
	Region string `yaml:"region" json:"region"`

	// Description 是可选的供人类阅读的描述。
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// EnforceLayer 是强制执法层 CIDR 白名单。
// 这是安全关键层——所有出站连接 MUST 的目标 IP 必须在此 CIDR 范围内。
type EnforceLayer struct {
	// 用于配置跟踪的版本号。
	Version int `yaml:"version" json:"version"`

	// Entries 是允许的 CIDR 地址段列表。
	Entries []EnforceEntry `yaml:"entries" json:"entries"`

	// cidrs 是已解析的 CIDR 地址段（从 Entries 计算得出）。
	cidrs []*net.IPNet

	// UpdatedAt 记录 CIDR 列表最后刷新的时间。
	UpdatedAt time.Time `yaml:"updated_at" json:"updated_at"`

	mu sync.RWMutex
}

// NewEnforceLayer 创建一个空的强制执法层。
func NewEnforceLayer() *EnforceLayer {
	return &EnforceLayer{
		Version: 1,
		Entries: make([]EnforceEntry, 0),
		cidrs:   make([]*net.IPNet, 0),
	}
}

// LoadEnforceFromYAML 从 YAML 文件加载强制执法层。
func LoadEnforceFromYAML(path string) (*EnforceLayer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("whitelist: failed to read enforce file %s: %w", path, err)
	}
	return ParseEnforceYAML(data)
}

// ParseEnforceYAML 从字节数据解析强制执法 YAML 内容。
func ParseEnforceYAML(data []byte) (*EnforceLayer, error) {
	return parseEnforceData(data, yaml.Unmarshal)
}

// ParseEnforceJSON 从字节数据解析强制执法 JSON 内容。
func ParseEnforceJSON(data []byte) (*EnforceLayer, error) {
	return parseEnforceData(data, json.Unmarshal)
}

// parseEnforceData 使用给定的反序列化器解析强制执法数据。
func parseEnforceData(data []byte, unmarshal func([]byte, interface{}) error) (*EnforceLayer, error) {
	enforce := NewEnforceLayer()
	if err := unmarshal(data, enforce); err != nil {
		return nil, fmt.Errorf("whitelist: failed to parse enforce: %w", err)
	}
	var compact struct {
		Allow []string `yaml:"allow" json:"allow"`
	}
	if len(enforce.Entries) == 0 {
		if err := unmarshal(data, &compact); err != nil {
			return nil, fmt.Errorf("whitelist: failed to parse enforce allow list: %w", err)
		}
		for _, cidr := range compact.Allow {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			enforce.Entries = append(enforce.Entries, EnforceEntry{
				CIDR:        cidr,
				Provider:    "inline",
				Region:      "any",
				Description: "inline allow list",
			})
		}
	}

	if err := enforce.parseCIDRs(); err != nil {
		return nil, fmt.Errorf("whitelist: failed to parse CIDRs: %w", err)
	}

	enforce.UpdatedAt = time.Now()
	return enforce, nil
}

// parseCIDRs 将所有 CIDR 字符串解析为 net.IPNet 对象。
func (el *EnforceLayer) parseCIDRs() error {
	el.cidrs = make([]*net.IPNet, 0, len(el.Entries))
	for _, entry := range el.Entries {
		_, ipNet, err := net.ParseCIDR(entry.CIDR)
		if err != nil {
			return fmt.Errorf("whitelist: invalid CIDR %q: %w", entry.CIDR, err)
		}
		el.cidrs = append(el.cidrs, ipNet)
	}
	return nil
}

// Contains 检查 IP 地址是否在任何允许的 CIDR 地址段内。
func (el *EnforceLayer) Contains(ip net.IP) bool {
	el.mu.RLock()
	defer el.mu.RUnlock()

	for _, cidr := range el.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ContainsString 检查 IP 地址字符串是否在任何允许的 CIDR 内。
func (el *EnforceLayer) ContainsString(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return el.Contains(ip)
}

// AddCIDR 向强制执法层添加一个 CIDR 地址段。
func (el *EnforceLayer) AddCIDR(entry EnforceEntry) error {
	_, ipNet, err := net.ParseCIDR(entry.CIDR)
	if err != nil {
		return fmt.Errorf("whitelist: invalid CIDR %q: %w", entry.CIDR, err)
	}

	el.mu.Lock()
	defer el.mu.Unlock()

	el.Entries = append(el.Entries, entry)
	el.cidrs = append(el.cidrs, ipNet)
	el.UpdatedAt = time.Now()
	return nil
}

// RefreshAWS 下载最新的 AWS IP 地址范围并更新强制执法层。
func (el *EnforceLayer) RefreshAWS(region string) error {
	resp, err := http.Get(AWSIPRangesURL)
	if err != nil {
		return fmt.Errorf("whitelist: failed to fetch AWS IP ranges: %w", err)
	}
	defer resp.Body.Close()

	var awsData struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Region     string `json:"region"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&awsData); err != nil {
		return fmt.Errorf("whitelist: failed to parse AWS IP ranges: %w", err)
	}

	el.mu.Lock()
	defer el.mu.Unlock()

	// 清除现有条目并重建
	el.Entries = make([]EnforceEntry, 0)
	el.cidrs = make([]*net.IPNet, 0)

	for _, prefix := range awsData.Prefixes {
		if prefix.Region == region {
			entry := EnforceEntry{
				CIDR:        prefix.IPPrefix,
				Provider:    "aws",
				Region:      region,
				Description: fmt.Sprintf("AWS %s %s", region, prefix.Service),
			}
			el.Entries = append(el.Entries, entry)
			_, ipNet, err := net.ParseCIDR(prefix.IPPrefix)
			if err == nil {
				el.cidrs = append(el.cidrs, ipNet)
			}
		}
	}

	// 同时添加 IPv6 前缀
	for _, prefix := range awsData.IPv6Prefixes {
		if prefix.Region == region {
			entry := EnforceEntry{
				CIDR:        prefix.IPv6Prefix,
				Provider:    "aws",
				Region:      region,
				Description: fmt.Sprintf("AWS %s %s (IPv6)", region, prefix.Service),
			}
			el.Entries = append(el.Entries, entry)
			_, ipNet, err := net.ParseCIDR(prefix.IPv6Prefix)
			if err == nil {
				el.cidrs = append(el.cidrs, ipNet)
			}
		}
	}

	el.UpdatedAt = time.Now()
	return nil
}

// Manager 结合两个白名单层并提供统一访问。
type Manager struct {
	Intent  *IntentLayer
	Enforce *EnforceLayer

	// lastRefresh 记录 CIDR 上次刷新的时间。
	lastRefresh time.Time

	// refreshInterval 控制 CIDR 刷新的频率。
	refreshInterval time.Duration

	mu sync.RWMutex
}

// NewManager 创建一个新的白名单管理器。
func NewManager(intent *IntentLayer, enforce *EnforceLayer) *Manager {
	return &Manager{
		Intent:          intent,
		Enforce:         enforce,
		refreshInterval: DefaultRefreshInterval,
	}
}

// LoadManager 从文件加载两个白名单层。
func LoadManager(intentPath, enforcePath string) (*Manager, error) {
	intent, err := LoadIntentFromYAML(intentPath)
	if err != nil {
		// 意图文件可能尚不存在——创建空的
		intent = NewIntentLayer()
	}

	enforce, err := LoadEnforceFromYAML(enforcePath)
	if err != nil {
		// 强制执法文件可能尚不存在——创建空的
		enforce = NewEnforceLayer()
	}

	return NewManager(intent, enforce), nil
}

// LoadManagerFromContent 从内联内容加载两个白名单层。
// 自动检测 JSON vs YAML：数据以 '{' 开头则为 JSON，否则为 YAML。
// 空切片创建空层。
func LoadManagerFromContent(intentData, enforceData []byte) (*Manager, error) {
	var intent *IntentLayer
	var enforce *EnforceLayer
	var err error

	if len(intentData) > 0 {
		if isJSON(intentData) {
			intent, err = ParseIntentJSON(intentData)
		} else {
			intent, err = ParseIntentYAML(intentData)
		}
		if err != nil {
			return nil, fmt.Errorf("whitelist: failed to parse intent: %w", err)
		}
	} else {
		intent = NewIntentLayer()
	}

	if len(enforceData) > 0 {
		if isJSON(enforceData) {
			enforce, err = ParseEnforceJSON(enforceData)
		} else {
			enforce, err = ParseEnforceYAML(enforceData)
		}
		if err != nil {
			return nil, fmt.Errorf("whitelist: failed to parse enforce: %w", err)
		}
	} else {
		enforce = NewEnforceLayer()
	}

	return NewManager(intent, enforce), nil
}

// isJSON 如果数据看起来像 JSON（修剪后以 '{' 开头）则返回 true。
func isJSON(data []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(data)), "{")
}

// CheckSNI 检查 SNI 是否通过意图层（关卡A）。
func (m *Manager) CheckSNI(sni string) error {
	if !m.Intent.Contains(sni) {
		return fmt.Errorf("%w: %s", ErrSNIRejected, sni)
	}
	return nil
}

// CheckIP 检查目标 IP 是否通过强制执法层（关卡B）。
func (m *Manager) CheckIP(ipStr string) error {
	if !m.Enforce.ContainsString(ipStr) {
		return fmt.Errorf("%w: %s", ErrIPRejected, ipStr)
	}
	return nil
}

// CheckDestination 同时检查 SNI 和 IP（关卡A + 关卡B）。
// 两者必须都通过才能进行连接。
func (m *Manager) CheckDestination(sni, destIP string) error {
	if err := m.CheckSNI(sni); err != nil {
		return err
	}
	if err := m.CheckIP(destIP); err != nil {
		return err
	}
	return nil
}

// RefreshIfNeeded 如果刷新间隔已过，则刷新强制执法层 CIDR。
func (m *Manager) RefreshIfNeeded(region string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if time.Since(m.lastRefresh) < m.refreshInterval {
		return nil
	}

	if err := m.Enforce.RefreshAWS(region); err != nil {
		return fmt.Errorf("whitelist: failed to refresh AWS CIDRs: %w", err)
	}

	m.lastRefresh = time.Now()
	return nil
}

// GetSiteInfo 返回站点的白名单条目和解析后的 IP 信息。
func (m *Manager) GetSiteInfo(sni string) (IntentEntry, bool) {
	return m.Intent.Get(sni)
}

// PassiveFallback 处理白名单检查失败的情况（P1：无可区分的失败路径）。
// 返回 nil 表示调用者应以与真实站点行为不可区分的方式
// 转发到真实站点或拒绝连接。
func (m *Manager) PassiveFallback(sni string) error {
	// 此方法作为文档点存在——实际的回退行为
	//（转发到真实站点或自然关闭连接）在
	// 中继处理器中实现。关键原则是：
	//
	// "当 A 或 B 失败时，行为与真实站点对于
	//  未知/意外请求的行为完全一致。"
	//
	// 没有特殊错误码，没有提前断开，没有时序差异。
	return ErrSNIRejected
}
