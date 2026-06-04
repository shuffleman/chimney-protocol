package whitelist

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestNewIntentLayer(t *testing.T) {
	il := NewIntentLayer()
	if il == nil {
		t.Fatal("NewIntentLayer returned nil")
	}
	if il.Version != 1 {
		t.Errorf("Version = %d, want 1", il.Version)
	}
	if il.Entries == nil {
		t.Error("Entries map is nil")
	}
}

func TestIntentLayer_AddContains(t *testing.T) {
	il := NewIntentLayer()

	entry := IntentEntry{
		SNI:         "example.com",
		Description: "测试站点",
	}

	il.Add(entry)

	if !il.Contains("example.com") {
		t.Error("Contains('example.com') = false, want true")
	}
	if !il.Contains("EXAMPLE.COM") { // 不区分大小写
		t.Error("Contains('EXAMPLE.COM') = false, want true (case insensitive)")
	}
	if il.Contains("not-in-list.com") {
		t.Error("Contains('not-in-list.com') = true, want false")
	}
}

func TestIntentLayer_Get(t *testing.T) {
	il := NewIntentLayer()

	entry := IntentEntry{
		SNI:         "test.example.com",
		Description: "Test entry",
	}
	il.Add(entry)

	got, ok := il.Get("test.example.com")
	if !ok {
		t.Fatal("Get returned not found")
	}
	if got.SNI != "test.example.com" {
		t.Errorf("SNI = %q, want %q", got.SNI, "test.example.com")
	}
	if got.Description != "Test entry" {
		t.Errorf("Description = %q, want %q", got.Description, "Test entry")
	}

	_, ok = il.Get("nonexistent.com")
	if ok {
		t.Error("Get for nonexistent entry returned ok=true")
	}
}

func TestIntentLayer_Remove(t *testing.T) {
	il := NewIntentLayer()

	il.Add(IntentEntry{SNI: "remove-me.com"})
	if !il.Contains("remove-me.com") {
		t.Fatal("Entry not added")
	}

	il.Remove("remove-me.com")
	if il.Contains("remove-me.com") {
		t.Error("Entry still present after Remove")
	}
}

func TestIntentLayer_List(t *testing.T) {
	il := NewIntentLayer()

	il.Add(IntentEntry{SNI: "a.com"})
	il.Add(IntentEntry{SNI: "b.com"})
	il.Add(IntentEntry{SNI: "c.com"})

	list := il.List()
	if len(list) != 3 {
		t.Errorf("List length = %d, want 3", len(list))
	}

	// 检查所有条目是否存在
	seen := make(map[string]bool)
	for _, sni := range list {
		seen[sni] = true
	}
	for _, expected := range []string{"a.com", "b.com", "c.com"} {
		if !seen[expected] {
			t.Errorf("Missing entry: %s", expected)
		}
	}
}

func TestLoadIntentFromYAML(t *testing.T) {
	// 创建临时 YAML 文件
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "intent.yaml")

	yamlContent := `
version: 1
entries:
  example.com:
    sni: example.com
    description: "Example site"
  test.org:
    sni: test.org
    description: "Test organization"
`
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write test YAML: %v", err)
	}

	il, err := LoadIntentFromYAML(yamlPath)
	if err != nil {
		t.Fatalf("LoadIntentFromYAML failed: %v", err)
	}

	if !il.Contains("example.com") {
		t.Error("Missing example.com")
	}
	if !il.Contains("test.org") {
		t.Error("Missing test.org")
	}
}

func TestNewEnforceLayer(t *testing.T) {
	el := NewEnforceLayer()
	if el == nil {
		t.Fatal("NewEnforceLayer returned nil")
	}
	if el.Entries == nil {
		t.Error("Entries slice is nil")
	}
}

func TestEnforceLayer_AddCIDR_Contains(t *testing.T) {
	el := NewEnforceLayer()

	err := el.AddCIDR(EnforceEntry{
		CIDR:     "10.0.0.0/8",
		Provider: "test",
		Region:   "test-region",
	})
	if err != nil {
		t.Fatalf("AddCIDR failed: %v", err)
	}

	tests := []struct {
		ip      string
		allowed bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"10.128.0.0", true},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"11.0.0.1", false},
	}

	for _, tc := range tests {
		got := el.ContainsString(tc.ip)
		if got != tc.allowed {
			t.Errorf("ContainsString(%q) = %v, want %v", tc.ip, got, tc.allowed)
		}
	}
}

func TestEnforceLayer_AddCIDR_InvalidCIDR(t *testing.T) {
	el := NewEnforceLayer()

	err := el.AddCIDR(EnforceEntry{
		CIDR: "not-a-valid-cidr",
	})
	if err == nil {
		t.Error("Expected error for invalid CIDR, got nil")
	}
}

func TestEnforceLayer_MultipleCIDRs(t *testing.T) {
	el := NewEnforceLayer()

	el.AddCIDR(EnforceEntry{CIDR: "192.168.0.0/16"})
	el.AddCIDR(EnforceEntry{CIDR: "10.0.0.0/8"})
	el.AddCIDR(EnforceEntry{CIDR: "172.16.0.0/12"})

	tests := []struct {
		ip      string
		allowed bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.20.0.1", true},
		{"8.8.8.8", false},
	}

	for _, tc := range tests {
		got := el.ContainsString(tc.ip)
		if got != tc.allowed {
			t.Errorf("ContainsString(%q) = %v, want %v", tc.ip, got, tc.allowed)
		}
	}
}

func TestLoadEnforceFromYAML(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "enforce.yaml")

	yamlContent := `
version: 1
entries:
  - cidr: "52.0.0.0/11"
    provider: "aws"
    region: "us-east-1"
  - cidr: "10.0.0.0/8"
    provider: "private"
    region: "local"
`
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write test YAML: %v", err)
	}

	el, err := LoadEnforceFromYAML(yamlPath)
	if err != nil {
		t.Fatalf("LoadEnforceFromYAML failed: %v", err)
	}

	if !el.ContainsString("52.0.0.1") {
		t.Error("Should contain 52.0.0.1")
	}
	if !el.ContainsString("10.1.2.3") {
		t.Error("Should contain 10.1.2.3")
	}
	if el.ContainsString("8.8.8.8") {
		t.Error("Should not contain 8.8.8.8")
	}
}

func TestManager_CheckDestination(t *testing.T) {
	intent := NewIntentLayer()
	intent.Add(IntentEntry{SNI: "allowed.com"})

	enforce := NewEnforceLayer()
	enforce.AddCIDR(EnforceEntry{CIDR: "52.0.0.0/11"})

	mgr := NewManager(intent, enforce)

	// Both checks pass
	err := mgr.CheckDestination("allowed.com", "52.0.0.1")
	if err != nil {
		t.Errorf("CheckDestination failed: %v", err)
	}

	// SNI not in whitelist
	err = mgr.CheckDestination("blocked.com", "52.0.0.1")
	if err == nil {
		t.Error("Expected error for blocked SNI")
	}

	// IP not in CIDR
	err = mgr.CheckDestination("allowed.com", "8.8.8.8")
	if err == nil {
		t.Error("Expected error for IP not in CIDR")
	}
}

func TestManager_CheckSNI(t *testing.T) {
	intent := NewIntentLayer()
	intent.Add(IntentEntry{SNI: "example.com"})

	mgr := NewManager(intent, NewEnforceLayer())

	if err := mgr.CheckSNI("example.com"); err != nil {
		t.Errorf("CheckSNI for allowed SNI: %v", err)
	}

	if err := mgr.CheckSNI("blocked.com"); err == nil {
		t.Error("Expected error for blocked SNI")
	}
}

func TestManager_CheckIP(t *testing.T) {
	enforce := NewEnforceLayer()
	enforce.AddCIDR(EnforceEntry{CIDR: "10.0.0.0/8"})

	mgr := NewManager(NewIntentLayer(), enforce)

	if err := mgr.CheckIP("10.1.2.3"); err != nil {
		t.Errorf("CheckIP for allowed IP: %v", err)
	}

	if err := mgr.CheckIP("192.168.1.1"); err == nil {
		t.Error("Expected error for blocked IP")
	}
}

func TestManager_LoadManager(t *testing.T) {
	tmpDir := t.TempDir()
	intentPath := filepath.Join(tmpDir, "intent.yaml")
	enforcePath := filepath.Join(tmpDir, "enforce.yaml")

	// 创建 intent 文件
	os.WriteFile(intentPath, []byte(`
version: 1
entries:
  test.com:
    sni: test.com
`), 0644)

	// 创建 enforce 文件
	os.WriteFile(enforcePath, []byte(`
version: 1
entries:
  - cidr: "192.168.0.0/16"
    provider: "test"
    region: "test"
`), 0644)

	mgr, err := LoadManager(intentPath, enforcePath)
	if err != nil {
		t.Fatalf("LoadManager failed: %v", err)
	}

	if !mgr.Intent.Contains("test.com") {
		t.Error("Intent not loaded correctly")
	}
	if !mgr.Enforce.ContainsString("192.168.1.1") {
		t.Error("Enforce not loaded correctly")
	}
}

func TestEnforceLayer_IPv6(t *testing.T) {
	el := NewEnforceLayer()

	err := el.AddCIDR(EnforceEntry{CIDR: "2001:db8::/32"})
	if err != nil {
		t.Fatalf("AddCIDR for IPv6 failed: %v", err)
	}

	if !el.ContainsString("2001:db8::1") {
		t.Error("Should contain 2001:db8::1")
	}
	if !el.ContainsString("2001:db8:ffff::1") {
		t.Error("Should contain 2001:db8:ffff::1")
	}
	if el.ContainsString("2001:db9::1") {
		t.Error("Should not contain 2001:db9::1")
	}
}

func BenchmarkIntentLayer_Contains(b *testing.B) {
	il := NewIntentLayer()
	for i := 0; i < 1000; i++ {
		il.Add(IntentEntry{SNI: fmt.Sprintf("site%d.example.com", i)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		il.Contains("site500.example.com")
	}
}

func BenchmarkEnforceLayer_Contains(b *testing.B) {
	el := NewEnforceLayer()
	// 添加约 50 个常见的 AWS CIDR
	cidrs := []string{
		"3.2.34.0/26", "3.2.35.0/24", "3.208.0.0/12", "3.224.0.0/12",
		"13.58.0.0/15", "18.204.0.0/14", "34.192.0.0/12", "44.192.0.0/11",
		"50.16.0.0/15", "52.0.0.0/11", "54.80.0.0/13", "54.88.0.0/14",
		"54.144.0.0/14", "54.160.0.0/13", "54.172.0.0/15", "54.196.0.0/15",
	}
	for _, cidr := range cidrs {
		el.AddCIDR(EnforceEntry{CIDR: cidr})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		el.ContainsString("52.0.0.1")
	}
}

// 确保错误类型正确
func TestErrorTypes(t *testing.T) {
	if ErrSNIRejected == nil {
		t.Error("ErrSNIRejected should not be nil")
	}
	if ErrIPRejected == nil {
		t.Error("ErrIPRejected should not be nil")
	}
	if ErrSiteNotFound == nil {
		t.Error("ErrSiteNotFound should not be nil")
	}
}
