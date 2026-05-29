package chimney

import (
	"net"
	"testing"
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
