package main

import (
	"net"
	"testing"
	"time"

	cfgpkg "github.com/shuffleman/chimney-protocol/internal/config"
	"github.com/shuffleman/chimney-protocol/internal/h2engine"
)

func TestTunnelConnDeliverFrameWaitsForFullStreamChannel(t *testing.T) {
	ch := make(chan *streamFrame, 1)
	ch <- &streamFrame{
		fh:      &h2engine.FrameHeader{StreamID: 1, Type: h2engine.FrameData},
		payload: []byte{0x02, 'a'},
	}

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	tc := &tunnelConn{
		Conn:    left,
		streams: map[uint32]chan *streamFrame{1: ch},
		quit:    make(chan struct{}),
		dead:    make(chan struct{}),
	}

	done := make(chan bool, 1)
	go func() {
		done <- tc.deliverFrame(
			&h2engine.FrameHeader{StreamID: 1, Type: h2engine.FrameData},
			[]byte{0x02, 'b'},
		)
	}()

	select {
	case <-done:
		t.Fatal("deliverFrame returned while stream channel was still full")
	case <-time.After(20 * time.Millisecond):
	}

	<-ch

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("deliverFrame reported failure after channel space became available")
		}
	case <-time.After(time.Second):
		t.Fatal("deliverFrame did not complete after channel space became available")
	}

	got := <-ch
	if string(got.payload) != string([]byte{0x02, 'b'}) {
		t.Fatalf("unexpected delivered payload: %v", got.payload)
	}
}

func TestApplyClientConfigUsesConfigValues(t *testing.T) {
	cfg := &cfgpkg.ClientConfig{
		RelayAddr:       "relay.example.com:443",
		SNI:             "cloudflare.com",
		DestAddr:        "example.com:80",
		PSK:             "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		UserID:          "alice",
		TagLen:          16,
		ListenAddr:      "127.0.0.1:1081",
		UTlsFingerprint: "firefox",
	}
	relayAddr := ""
	sni := ""
	destAddr := ""
	pskHex := ""
	tagLen := 0
	listenAddr := ""
	fingerprint := ""
	userID := ""

	applyClientConfig(cfg, nil, &relayAddr, &sni, &destAddr, &pskHex, &tagLen, &listenAddr, &fingerprint, &userID)

	if relayAddr != cfg.RelayAddr || sni != cfg.SNI || destAddr != cfg.DestAddr {
		t.Fatalf("connection fields were not applied: relay=%q sni=%q dest=%q", relayAddr, sni, destAddr)
	}
	if pskHex != cfg.PSK || userID != cfg.UserID || tagLen != cfg.TagLen {
		t.Fatalf("auth fields were not applied: psk=%q user=%q tagLen=%d", pskHex, userID, tagLen)
	}
	if listenAddr != cfg.ListenAddr || fingerprint != cfg.UTlsFingerprint {
		t.Fatalf("client fields were not applied: listen=%q fp=%q", listenAddr, fingerprint)
	}
}

func TestApplyClientConfigKeepsExplicitFlags(t *testing.T) {
	cfg := &cfgpkg.ClientConfig{
		RelayAddr:       "relay.example.com:443",
		SNI:             "cloudflare.com",
		DestAddr:        "example.com:80",
		UserID:          "alice",
		TagLen:          16,
		ListenAddr:      "127.0.0.1:1081",
		UTlsFingerprint: "firefox",
	}
	relayAddr := "127.0.0.1:8444"
	sni := ""
	destAddr := ""
	pskHex := ""
	tagLen := 0
	listenAddr := ""
	fingerprint := "chrome"
	userID := ""

	applyClientConfig(
		cfg,
		map[string]bool{"relay": true, "fingerprint": true},
		&relayAddr,
		&sni,
		&destAddr,
		&pskHex,
		&tagLen,
		&listenAddr,
		&fingerprint,
		&userID,
	)

	if relayAddr != "127.0.0.1:8444" {
		t.Fatalf("explicit relay flag was overwritten: %q", relayAddr)
	}
	if fingerprint != "chrome" {
		t.Fatalf("explicit fingerprint flag was overwritten: %q", fingerprint)
	}
	if sni != cfg.SNI || destAddr != cfg.DestAddr || userID != cfg.UserID {
		t.Fatalf("non-explicit config fields were not applied")
	}
}
