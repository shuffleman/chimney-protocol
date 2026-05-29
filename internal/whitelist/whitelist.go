// Package whitelist implements the two-layer whitelist system (Part II §10):
//
// Intent layer (配置): A list of allowed site names (SNI values).
// Writing wrong entries here only makes that site unavailable — not fatal.
//
// Enforce layer (强制执法): Cloud provider/region CIDR blocks.
// The relay MUST only connect to destination IPs within these CIDRs.
// This is the security-critical layer that ensures the relay's outbound
// connections stay within the same cloud region as the whitelisted sites.
//
// B (whitelist security property) holds if and only if:
//   - The relay is hosted in the same cloud/region as the whitelisted sites
//   - All outbound connections are to IPs within the region's CIDR blocks
//
// When a censor connects to the relay IP, the relay forwards to the real site,
// which returns its genuine certificate. The censor cannot distinguish between
// "relay is the real site" and "relay forwards to the real site" because
// both are in the same cloud region.
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
	// DefaultIntentFile is the default path for the intent-layer whitelist.
	DefaultIntentFile = "config/intent.yaml"

	// DefaultEnforceFile is the default path for the enforce-layer CIDR config.
	DefaultEnforceFile = "config/enforce.yaml"

	// DefaultRefreshInterval for CIDR lists from cloud providers.
	DefaultRefreshInterval = 24 * time.Hour

	// AW SIPRangesURL is the URL for AWS IP ranges.
	AWSIPRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
)

var (
	// ErrSNIRejected means the SNI is not in the intent whitelist.
	ErrSNIRejected = errors.New("whitelist: SNI not in intent whitelist")

	// ErrIPRejected means the destination IP is not in the enforce CIDR ranges.
	ErrIPRejected = errors.New("whitelist: destination IP not in enforce CIDR ranges")

	// ErrSiteNotFound means the requested site is not in the whitelist.
	ErrSiteNotFound = errors.New("whitelist: site not found")
)

// IntentEntry is a single entry in the intent-layer whitelist.
type IntentEntry struct {
	// SNI is the Server Name Indicator (TLS SNI) value.
	SNI string `yaml:"sni" json:"sni"`

	// Description is an optional human-readable description.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// SettingsSnapshot contains captured HTTP/2 SETTINGS from this site.
	// Filled at runtime from calibration data.
	SettingsSnapshot map[string]interface{} `yaml:"settings_snapshot,omitempty" json:"settings_snapshot,omitempty"`

	// ProfileModel contains the traffic profile model for this site.
	// Filled at runtime from calibration data.
	ProfileModel map[string]interface{} `yaml:"profile_model,omitempty" json:"profile_model,omitempty"`
}

// IntentLayer is the intent-layer whitelist (site names).
type IntentLayer struct {
	// Version for configuration tracking.
	Version int `yaml:"version" json:"version"`

	// Entries maps SNI (lowercase) to its whitelist entry.
	Entries map[string]IntentEntry `yaml:"entries" json:"entries"`

	// UpdatedAt tracks when the whitelist was last modified.
	UpdatedAt time.Time `yaml:"updated_at" json:"updated_at"`

	mu sync.RWMutex
}

// NewIntentLayer creates an empty intent layer.
func NewIntentLayer() *IntentLayer {
	return &IntentLayer{
		Version: 1,
		Entries: make(map[string]IntentEntry),
	}
}

// LoadIntentFromYAML loads the intent layer from a YAML file.
func LoadIntentFromYAML(path string) (*IntentLayer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("whitelist: failed to read intent file %s: %w", path, err)
	}

	intent := NewIntentLayer()
	if err := yaml.Unmarshal(data, intent); err != nil {
		return nil, fmt.Errorf("whitelist: failed to parse intent YAML: %w", err)
	}

	// Normalize SNIs to lowercase
	normalized := make(map[string]IntentEntry, len(intent.Entries))
	for sni, entry := range intent.Entries {
		entry.SNI = strings.ToLower(strings.TrimSpace(entry.SNI))
		normalized[strings.ToLower(strings.TrimSpace(sni))] = entry
	}
	intent.Entries = normalized
	intent.UpdatedAt = time.Now()

	return intent, nil
}

// SaveToYAML saves the intent layer to a YAML file.
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

// Contains checks if an SNI is in the intent whitelist.
func (il *IntentLayer) Contains(sni string) bool {
	il.mu.RLock()
	defer il.mu.RUnlock()

	sni = strings.ToLower(strings.TrimSpace(sni))
	_, ok := il.Entries[sni]
	return ok
}

// Get returns the whitelist entry for an SNI.
func (il *IntentLayer) Get(sni string) (IntentEntry, bool) {
	il.mu.RLock()
	defer il.mu.RUnlock()

	sni = strings.ToLower(strings.TrimSpace(sni))
	entry, ok := il.Entries[sni]
	return entry, ok
}

// Add adds or updates a whitelist entry.
func (il *IntentLayer) Add(entry IntentEntry) {
	il.mu.Lock()
	defer il.mu.Unlock()

	sni := strings.ToLower(strings.TrimSpace(entry.SNI))
	entry.SNI = sni
	il.Entries[sni] = entry
	il.UpdatedAt = time.Now()
}

// Remove removes an SNI from the whitelist.
func (il *IntentLayer) Remove(sni string) {
	il.mu.Lock()
	defer il.mu.Unlock()

	sni = strings.ToLower(strings.TrimSpace(sni))
	delete(il.Entries, sni)
	il.UpdatedAt = time.Now()
}

// List returns all SNIs in the whitelist.
func (il *IntentLayer) List() []string {
	il.mu.RLock()
	defer il.mu.RUnlock()

	snis := make([]string, 0, len(il.Entries))
	for sni := range il.Entries {
		snis = append(snis, sni)
	}
	return snis
}

// EnforceEntry is a CIDR block for the enforce layer.
type EnforceEntry struct {
	// CIDR is the IP CIDR block (e.g., "52.0.0.0/8" for AWS us-east-1).
	CIDR string `yaml:"cidr" json:"cidr"`

	// Provider is the cloud provider name (e.g., "aws", "gcp", "azure").
	Provider string `yaml:"provider" json:"provider"`

	// Region is the cloud region (e.g., "us-east-1").
	Region string `yaml:"region" json:"region"`

	// Description is an optional human-readable description.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// EnforceLayer is the enforce-layer CIDR whitelist.
// This is the security-critical layer — all outbound connections MUST
// have destination IPs within these CIDRs.
type EnforceLayer struct {
	// Version for configuration tracking.
	Version int `yaml:"version" json:"version"`

	// Entries is the list of allowed CIDR blocks.
	Entries []EnforceEntry `yaml:"entries" json:"entries"`

	// cidrs is the parsed CIDR blocks (computed from Entries).
	cidrs []*net.IPNet

	// UpdatedAt tracks when the CIDR list was last refreshed.
	UpdatedAt time.Time `yaml:"updated_at" json:"updated_at"`

	mu sync.RWMutex
}

// NewEnforceLayer creates an empty enforce layer.
func NewEnforceLayer() *EnforceLayer {
	return &EnforceLayer{
		Version: 1,
		Entries: make([]EnforceEntry, 0),
		cidrs:   make([]*net.IPNet, 0),
	}
}

// LoadEnforceFromYAML loads the enforce layer from a YAML file.
func LoadEnforceFromYAML(path string) (*EnforceLayer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("whitelist: failed to read enforce file %s: %w", path, err)
	}

	enforce := NewEnforceLayer()
	if err := yaml.Unmarshal(data, enforce); err != nil {
		return nil, fmt.Errorf("whitelist: failed to parse enforce YAML: %w", err)
	}

	if err := enforce.parseCIDRs(); err != nil {
		return nil, fmt.Errorf("whitelist: failed to parse CIDRs: %w", err)
	}

	enforce.UpdatedAt = time.Now()
	return enforce, nil
}

// parseCIDRs parses all CIDR strings into net.IPNet objects.
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

// Contains checks if an IP address is within any of the allowed CIDR blocks.
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

// ContainsString checks if an IP address string is within any allowed CIDR.
func (el *EnforceLayer) ContainsString(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return el.Contains(ip)
}

// AddCIDR adds a CIDR block to the enforce layer.
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

// RefreshAWS downloads the latest AWS IP ranges and updates the enforce layer.
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

	// Clear existing entries and rebuild
	el.Entries = make([]EnforceEntry, 0)
	el.cidrs = make([]*net.IPNet, 0)

	for _, prefix := range awsData.Prefixes {
		if prefix.Region == region {
			entry := EnforceEntry{
				CIDR:     prefix.IPPrefix,
				Provider: "aws",
				Region:   region,
				Description: fmt.Sprintf("AWS %s %s", region, prefix.Service),
			}
			el.Entries = append(el.Entries, entry)
			_, ipNet, err := net.ParseCIDR(prefix.IPPrefix)
			if err == nil {
				el.cidrs = append(el.cidrs, ipNet)
			}
		}
	}

	// Also add IPv6 prefixes
	for _, prefix := range awsData.IPv6Prefixes {
		if prefix.Region == region {
			entry := EnforceEntry{
				CIDR:     prefix.IPv6Prefix,
				Provider: "aws",
				Region:   region,
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

// Manager combines both whitelist layers and provides unified access.
type Manager struct {
	Intent  *IntentLayer
	Enforce *EnforceLayer

	// lastRefresh tracks when CIDRs were last refreshed.
	lastRefresh time.Time

	// refreshInterval controls how often CIDRs are refreshed.
	refreshInterval time.Duration

	mu sync.RWMutex
}

// NewManager creates a new whitelist manager.
func NewManager(intent *IntentLayer, enforce *EnforceLayer) *Manager {
	return &Manager{
		Intent:          intent,
		Enforce:         enforce,
		refreshInterval: DefaultRefreshInterval,
	}
}

// LoadManager loads both whitelist layers from files.
func LoadManager(intentPath, enforcePath string) (*Manager, error) {
	intent, err := LoadIntentFromYAML(intentPath)
	if err != nil {
		// Intent file may not exist yet — create empty
		intent = NewIntentLayer()
	}

	enforce, err := LoadEnforceFromYAML(enforcePath)
	if err != nil {
		// Enforce file may not exist yet — create empty
		enforce = NewEnforceLayer()
	}

	return NewManager(intent, enforce), nil
}

// CheckSNI checks if an SNI passes the intent layer (关卡A).
func (m *Manager) CheckSNI(sni string) error {
	if !m.Intent.Contains(sni) {
		return fmt.Errorf("%w: %s", ErrSNIRejected, sni)
	}
	return nil
}

// CheckIP checks if a destination IP passes the enforce layer (关卡B).
func (m *Manager) CheckIP(ipStr string) error {
	if !m.Enforce.ContainsString(ipStr) {
		return fmt.Errorf("%w: %s", ErrIPRejected, ipStr)
	}
	return nil
}

// CheckDestination checks both SNI and IP (关卡A + 关卡B).
// Both must pass for the connection to proceed.
func (m *Manager) CheckDestination(sni, destIP string) error {
	if err := m.CheckSNI(sni); err != nil {
		return err
	}
	if err := m.CheckIP(destIP); err != nil {
		return err
	}
	return nil
}

// RefreshIfNeeded refreshes the enforce layer CIDRs if the refresh interval has passed.
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

// GetSiteInfo returns the whitelist entry and resolved IP info for a site.
func (m *Manager) GetSiteInfo(sni string) (IntentEntry, bool) {
	return m.Intent.Get(sni)
}

// PassiveFallback handles the case when whitelist checks fail (P1: No distinguishable failure path).
// Returns nil to indicate the caller should forward to the real site or reject
// in a way indistinguishable from the real site's behavior.
func (m *Manager) PassiveFallback(sni string) error {
	// This method exists as a documentation point — the actual fallback behavior
	// (forwarding to the real site or closing the connection naturally) is
	// implemented in the relay handler. The key principle is:
	//
	// "When A or B fails, behave exactly as the real site would for an
	//  unknown/unexpected request."
	//
	// No special error codes, no early disconnect, no timing differences.
	return ErrSNIRejected
}
