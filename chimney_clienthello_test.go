package chimney

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// genClientHelloRecord 用 uTLS 生成一条真实的 ClientHello,返回完整 TLS 记录字节
// (含 5 字节记录头),作为精确指纹校准的测试夹具。
func genClientHelloRecord(t *testing.T) []byte {
	t.Helper()
	uc := utls.UClient(&net.TCPConn{}, &utls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	hello := uc.HandshakeState.Hello.Raw
	rec := make([]byte, 5+len(hello))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	rec[3] = byte(len(hello) >> 8)
	rec[4] = byte(len(hello) & 0xff)
	copy(rec[5:], hello)
	return rec
}

func TestLoadAndBuildClientHelloSpec(t *testing.T) {
	rec := genClientHelloRecord(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com.clienthello")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(rec)+"\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	raw, err := loadClientHelloRaw(path)
	if err != nil {
		t.Fatalf("loadClientHelloRaw: %v", err)
	}
	if len(raw) != len(rec) {
		t.Fatalf("loaded %d bytes, want %d", len(raw), len(rec))
	}

	spec, err := buildClientHelloSpec(raw)
	if err != nil {
		t.Fatalf("buildClientHelloSpec: %v", err)
	}
	if len(spec.Extensions) == 0 {
		t.Error("rebuilt spec has no extensions")
	}

	// spec 应可应用到一条 HelloCustom 连接(证明运行时握手路径可用)。
	uc := utls.UClient(&net.TCPConn{}, &utls.Config{ServerName: "relay.example.com"}, utls.HelloCustom)
	if err := uc.ApplyPreset(spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState after ApplyPreset: %v", err)
	}
}

func TestLoadClientHelloRaw_Errors(t *testing.T) {
	dir := t.TempDir()

	badHex := filepath.Join(dir, "bad.hex")
	os.WriteFile(badHex, []byte("zzzz"), 0o644)

	notHello := filepath.Join(dir, "nothello.hex")
	os.WriteFile(notHello, []byte(hex.EncodeToString([]byte{0x17, 0x03, 0x01, 0x00, 0x02, 0x00, 0x00})), 0o644)

	for _, tt := range []struct {
		name, path string
	}{
		{"missing file", filepath.Join(dir, "nope.hex")},
		{"bad hex", badHex},
		{"not a clienthello", notHello},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := loadClientHelloRaw(tt.path); err == nil {
				t.Errorf("expected error for %q", tt.name)
			}
		})
	}
}

func TestNormalize_ClientHelloFile(t *testing.T) {
	rec := genClientHelloRecord(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good.clienthello")
	os.WriteFile(good, []byte(hex.EncodeToString(rec)), 0o644)

	base := func() Config {
		return Config{
			RelayAddr: "relay:443",
			SNI:       "example.com",
			UserID:    "550e8400-e29b-41d4-a716-446655440000",
		}
	}

	// 有效精确指纹文件 → 通过。
	cfg := base()
	cfg.ClientHelloFile = good
	if err := cfg.Normalize(); err != nil {
		t.Errorf("Normalize with valid ClientHelloFile: %v", err)
	}

	// 无效文件 → Normalize 报错(尽早暴露)。
	cfg2 := base()
	cfg2.ClientHelloFile = filepath.Join(dir, "missing.clienthello")
	if err := cfg2.Normalize(); err == nil {
		t.Error("Normalize should fail on missing ClientHelloFile")
	}
}
