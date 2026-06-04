package chimney

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestParseFingerprint_Valid(t *testing.T) {
	tests := []string{
		"chrome", "chrome-120", "chrome-120-pq",
		"firefox", "firefox-105",
		"safari", "safari-16",
		"ios", "ios-14",
		"edge", "edge-106",
		"android",
		"360", "360-11",
		"qq", "qq-11",
		"randomized", "randomized-alpn", "randomized-noalpn",
		"golang",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			id, err := parseFingerprint(name)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if id.Client == "" && id.Version == "" {
				t.Errorf("empty ClientHelloID returned")
			}
		})
	}
}

func TestParseFingerprint_Invalid(t *testing.T) {
	_, err := parseFingerprint("nonexistent-browser")
	if err == nil {
		t.Error("expected error for unknown fingerprint")
	}
}

func TestParseFingerprint_CaseInsensitive(t *testing.T) {
	id1, err1 := parseFingerprint("Chrome")
	id2, err2 := parseFingerprint("CHROME")
	id3, err3 := parseFingerprint("chrome")

	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatal("unexpected error for case variants")
	}
	if id1 != id2 || id2 != id3 {
		t.Error("case-insensitive lookup should return same ID")
	}
}

func TestStreamConnSatisfiesNetConn(t *testing.T) {
	// Compile-time check: streamConn implements net.Conn
	var _ net.Conn = (*streamConn)(nil)
}

func TestAddr(t *testing.T) {
	a := addr{"tcp", "127.0.0.1:443"}
	if a.Network() != "tcp" {
		t.Errorf("expected network tcp, got %s", a.Network())
	}
	if a.String() != "127.0.0.1:443" {
		t.Errorf("expected 127.0.0.1:443, got %s", a.String())
	}
}

func TestStreamConnReadDeadline(t *testing.T) {
	c := &streamConn{
		t:  &tunnel{quit: make(chan struct{})},
		ch: make(chan *streamFrame),
	}
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	_, err := c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected net timeout error, got %T %v", err, err)
	}
}

func TestStreamConnSetReadDeadlineWakesBlockedRead(t *testing.T) {
	c := &streamConn{
		t:  &tunnel{quit: make(chan struct{})},
		ch: make(chan *streamFrame),
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		errCh <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if err := c.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("expected net timeout error, got %T %v", err, err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Read was not woken by SetReadDeadline")
	}
}

func TestStreamConnWriteDeadlineExpired(t *testing.T) {
	c := &streamConn{
		t:  &tunnel{quit: make(chan struct{})},
		ch: make(chan *streamFrame),
	}
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}

	_, err := c.Write([]byte("x"))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected net timeout error, got %T %v", err, err)
	}
}

func TestListenPacketContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := &Dialer{}
	_, err := d.ListenPacket(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestListenPacketRejectsSecondPacketConn(t *testing.T) {
	tun := &tunnel{
		streams: make(map[uint32]chan *streamFrame),
		quit:    make(chan struct{}),
	}
	d := &Dialer{pool: []*tunnel{tun}}

	if _, err := d.ListenPacket(context.Background()); err != nil {
		t.Fatalf("first ListenPacket failed: %v", err)
	}
	if _, err := d.ListenPacket(context.Background()); err == nil {
		t.Fatal("expected second ListenPacket to fail")
	}
}

func TestNewDialerRequiresCredentials(t *testing.T) {
	_, err := NewDialer(Config{
		RelayAddr: "127.0.0.1:1",
		SNI:       "example.com",
	})
	if err == nil {
		t.Fatal("expected missing credentials error")
	}
}

func TestConfigFromYAMLAppliesDefaultsAndDerivesPSK(t *testing.T) {
	cfg, err := ConfigFromYAML([]byte(`
relay_addr: "relay.example.com:443"
sni: "cloudflare.com"
user_id: "550e8400-e29b-41d4-a716-446655440000"
pool_size: 2
connect_timeout: 2s
handshake_timeout: 3s
`))
	if err != nil {
		t.Fatalf("ConfigFromYAML failed: %v", err)
	}
	if cfg.PSK == "" {
		t.Fatal("expected PSK to be derived from user_id")
	}
	if cfg.TagLen != 16 {
		t.Fatalf("TagLen = %d, want 16", cfg.TagLen)
	}
	if cfg.Fingerprint != "chrome" {
		t.Fatalf("Fingerprint = %q, want chrome", cfg.Fingerprint)
	}
	if cfg.ConnectTimeout != 2*time.Second {
		t.Fatalf("ConnectTimeout = %v, want 2s", cfg.ConnectTimeout)
	}
	if cfg.HandshakeTimeout != 3*time.Second {
		t.Fatalf("HandshakeTimeout = %v, want 3s", cfg.HandshakeTimeout)
	}
	if cfg.PoolSize != 2 {
		t.Fatalf("PoolSize = %d, want 2", cfg.PoolSize)
	}
}

func TestConfigNormalizeRejectsInvalidPSK(t *testing.T) {
	cfg := Config{
		RelayAddr: "relay.example.com:443",
		SNI:       "cloudflare.com",
		PSK:       "not-hex",
	}
	if err := cfg.Normalize(); err == nil {
		t.Fatal("expected invalid PSK error")
	}
}

func TestDialerDialContextMatchesHTTPTransport(t *testing.T) {
	var d *Dialer
	transport := &http.Transport{
		DialContext: d.DialContext,
	}
	if transport.DialContext == nil {
		t.Fatal("DialContext adapter is nil")
	}
}
