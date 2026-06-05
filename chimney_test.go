package chimney

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/dilution"
	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/profile"
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

func TestDefaultTLSNextProtosPrefersH2(t *testing.T) {
	protos := defaultTLSNextProtos()
	if len(protos) != 2 {
		t.Fatalf("defaultTLSNextProtos length = %d, want 2", len(protos))
	}
	if protos[0] != "h2" || protos[1] != "http/1.1" {
		t.Fatalf("defaultTLSNextProtos = %v, want [h2 http/1.1]", protos)
	}
}

func TestStreamConnSatisfiesNetConn(t *testing.T) {
	// 编译时检查：streamConn 实现了 net.Conn 接口
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

func TestStreamConnCloseWakesBlockedRead(t *testing.T) {
	tun := &tunnel{
		streams: make(map[uint32]chan *streamFrame),
		quit:    make(chan struct{}),
	}
	ch := make(chan *streamFrame)
	tun.streams[1] = ch
	c := newStreamConn(tun, 1, ch, cmdTCP)

	errCh := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		errCh <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed, got %T %v", err, err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Read was not woken by Close")
	}
	if _, ok := tun.streams[1]; ok {
		t.Fatal("stream was not unregistered on Close")
	}
}

func TestStreamConnCloseIsIdempotentAndWriteFailsAfterClose(t *testing.T) {
	tun := &tunnel{
		streams: make(map[uint32]chan *streamFrame),
		quit:    make(chan struct{}),
	}
	ch := make(chan *streamFrame, 1)
	tun.streams[1] = ch
	c := newStreamConn(tun, 1, ch, cmdTCP)

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close, got %T %v", err, err)
	}
}

func TestEnsureTunnelReturnsReconnectErrorInsteadOfDeadTunnel(t *testing.T) {
	dead := make(chan struct{})
	close(dead)
	d := &Dialer{
		config: Config{
			RelayAddr:      "127.0.0.1:1",
			ConnectTimeout: 10 * time.Millisecond,
		},
		pool: []*tunnel{{
			dead: dead,
		}},
	}

	tun, err := d.ensureTunnel(0)
	if err == nil {
		t.Fatal("expected reconnect error")
	}
	if tun != nil {
		t.Fatal("expected no tunnel when reconnect fails")
	}
	if !strings.Contains(err.Error(), "chimney: reconnect failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDialContextReturnsReconnectErrorInsteadOfUsingDeadTunnel(t *testing.T) {
	dead := make(chan struct{})
	close(dead)
	d := &Dialer{
		config: Config{
			RelayAddr:      "127.0.0.1:1",
			ConnectTimeout: 10 * time.Millisecond,
		},
		pool: []*tunnel{{
			dead: dead,
		}},
	}

	_, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected reconnect error")
	}
	if !strings.Contains(err.Error(), "chimney: reconnect failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDialContextAttemptsAllPoolSlotsBeforeReturningReconnectError(t *testing.T) {
	deadA := make(chan struct{})
	close(deadA)
	deadB := make(chan struct{})
	close(deadB)
	attempts := 0
	d := &Dialer{
		pool: []*tunnel{
			{dead: deadA},
			{dead: deadB},
		},
		dialNew: func(Config, *profile.Model, *dilution.Provider) (*tunnel, error) {
			attempts++
			return nil, fmt.Errorf("dial attempt %d", attempts)
		},
	}

	_, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil {
		t.Fatal("expected reconnect error")
	}
	if attempts != 2 {
		t.Fatalf("DialContext attempted %d slots, want 2", attempts)
	}
	if !strings.Contains(err.Error(), "dial attempt 2") {
		t.Fatalf("unexpected final error: %v", err)
	}
}

func TestTunnelDialContextReturnsClosedForDeadTunnel(t *testing.T) {
	dead := make(chan struct{})
	close(dead)
	tun := &tunnel{
		dead: dead,
	}

	_, err := tun.dialContext(context.Background(), "example.com:443")
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %T %v", err, err)
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

func TestListenPacketAllowsMultiplePacketConns(t *testing.T) {
	tun := &tunnel{
		streams: make(map[uint32]chan *streamFrame),
		quit:    make(chan struct{}),
		dead:    make(chan struct{}),
		h2Eng:   h2engine.NewEngine(h2engine.DefaultSettings(), nil),
	}
	d := &Dialer{pool: []*tunnel{tun}}

	pc1, err := d.ListenPacket(context.Background())
	if err != nil {
		t.Fatalf("first ListenPacket failed: %v", err)
	}

	pc2, err := d.ListenPacket(context.Background())
	if err != nil {
		t.Fatalf("second ListenPacket failed: %v", err)
	}

	if len(tun.streams) != 2 {
		t.Fatalf("registered UDP streams = %d, want 2", len(tun.streams))
	}
	if pc1.(*udpConn).stream.streamID == pc2.(*udpConn).stream.streamID {
		t.Fatal("multiple UDP packet conns reused the same stream ID")
	}
}

func TestUDPConnCloseWakesBlockedReadFrom(t *testing.T) {
	tun := &tunnel{
		streams: make(map[uint32]chan *streamFrame),
		quit:    make(chan struct{}),
		dead:    make(chan struct{}),
		h2Eng:   h2engine.NewEngine(h2engine.DefaultSettings(), nil),
	}
	d := &Dialer{pool: []*tunnel{tun}}
	pc, err := d.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pc.(*udpConn).stream.t.h2Eng = nil

	errCh := make(chan error, 1)
	go func() {
		_, _, err := pc.ReadFrom(make([]byte, 1))
		errCh <- err
	}()

	time.Sleep(10 * time.Millisecond)
	_ = pc.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed, got %T %v", err, err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked ReadFrom was not woken by Close")
	}
}

func TestEncodeDatagramSupportsUDPAddrAndDomainAddr(t *testing.T) {
	ipv4 := encodeDatagram(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}, []byte("q"))
	if want := []byte{0x01, 192, 0, 2, 1, 0, 53, 'q'}; !bytes.Equal(ipv4, want) {
		t.Fatalf("unexpected IPv4 datagram: %v", ipv4)
	}

	ipv6 := encodeDatagram(&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 853}, []byte("q"))
	if len(ipv6) != 20 || ipv6[0] != 0x04 || ipv6[17] != 3 || ipv6[18] != 85 || ipv6[19] != 'q' {
		t.Fatalf("unexpected IPv6 datagram: %v", ipv6)
	}

	domain := encodeDatagram(addr{"udp", "cloudflare-dns.com:443"}, []byte("q"))
	want := append([]byte{0x03, byte(len("cloudflare-dns.com"))}, []byte("cloudflare-dns.com")...)
	want = append(want, 1, 187, 'q')
	if !bytes.Equal(domain, want) {
		t.Fatalf("unexpected domain datagram: %v", domain)
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
