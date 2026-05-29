package keyderiv

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

func TestGeneratePSK(t *testing.T) {
	psk, err := GeneratePSK(32)
	if err != nil {
		t.Fatalf("GeneratePSK failed: %v", err)
	}
	if len(psk) != 32 {
		t.Errorf("PSK length = %d, want 32", len(psk))
	}

	// Ensure PSK is random (not all zeros)
	allZero := true
	for _, b := range psk {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("PSK is all zeros, expected random value")
	}
}

func TestDeriver_DeriveAuthKey(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		t.Fatalf("Failed to generate PSK: %v", err)
	}

	deriver := NewDeriver(psk)

	serverRandom := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		t.Fatalf("Failed to generate ServerRandom: %v", err)
	}

	kAuth1, err := deriver.DeriveAuthKey(serverRandom)
	if err != nil {
		t.Fatalf("DeriveAuthKey failed: %v", err)
	}
	if len(kAuth1) != DefaultKeyLen {
		t.Errorf("K_auth length = %d, want %d", len(kAuth1), DefaultKeyLen)
	}

	// Same inputs → same key
	kAuth2, err := deriver.DeriveAuthKey(serverRandom)
	if err != nil {
		t.Fatalf("DeriveAuthKey second call failed: %v", err)
	}
	if !bytes.Equal(kAuth1, kAuth2) {
		t.Error("DeriveAuthKey not deterministic: same inputs produced different keys")
	}

	// Different ServerRandom → different key
	serverRandom[0] ^= 0xFF
	kAuth3, err := deriver.DeriveAuthKey(serverRandom)
	if err != nil {
		t.Fatalf("DeriveAuthKey with modified random failed: %v", err)
	}
	if bytes.Equal(kAuth1, kAuth3) {
		t.Error("Different ServerRandom produced same K_auth")
	}
}

func TestDeriver_DeriveSessionKey(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		t.Fatalf("Failed to generate PSK: %v", err)
	}

	deriver := NewDeriver(psk)

	serverRandom := make([]byte, 32)
	clientRandom := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		t.Fatalf("Failed to generate ServerRandom: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, clientRandom); err != nil {
		t.Fatalf("Failed to generate ClientRandom: %v", err)
	}

	kSess1, err := deriver.DeriveSessionKey(serverRandom, clientRandom)
	if err != nil {
		t.Fatalf("DeriveSessionKey failed: %v", err)
	}
	if len(kSess1) != DefaultKeyLen {
		t.Errorf("K_sess length = %d, want %d", len(kSess1), DefaultKeyLen)
	}

	// Same inputs → same key
	kSess2, err := deriver.DeriveSessionKey(serverRandom, clientRandom)
	if err != nil {
		t.Fatalf("DeriveSessionKey second call failed: %v", err)
	}
	if !bytes.Equal(kSess1, kSess2) {
		t.Error("DeriveSessionKey not deterministic")
	}

	// Different ClientRandom → different key
	clientRandom[0] ^= 0xFF
	kSess3, err := deriver.DeriveSessionKey(serverRandom, clientRandom)
	if err != nil {
		t.Fatalf("DeriveSessionKey with modified random failed: %v", err)
	}
	if bytes.Equal(kSess1, kSess3) {
		t.Error("Different ClientRandom produced same K_sess")
	}
}

func TestDeriver_DeriveAuthKey_InvalidLength(t *testing.T) {
	deriver := NewDeriver([]byte("test-psk"))

	// ServerRandom must be 32 bytes
	_, err := deriver.DeriveAuthKey([]byte("too-short"))
	if err == nil {
		t.Error("Expected error for short ServerRandom, got nil")
	}

	_, err = deriver.DeriveAuthKey(make([]byte, 33))
	if err == nil {
		t.Error("Expected error for long ServerRandom, got nil")
	}
}

func TestDeriver_DeriveSessionKey_InvalidLength(t *testing.T) {
	deriver := NewDeriver([]byte("test-psk"))

	_, err := deriver.DeriveSessionKey([]byte("short"), make([]byte, 32))
	if err == nil {
		t.Error("Expected error for short ServerRandom, got nil")
	}

	_, err = deriver.DeriveSessionKey(make([]byte, 32), []byte("short"))
	if err == nil {
		t.Error("Expected error for short ClientRandom, got nil")
	}
}

func TestDeriver_AuthTag(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		t.Fatalf("Failed to generate PSK: %v", err)
	}

	deriver := NewDeriver(psk)

	serverRandom := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		t.Fatalf("Failed to generate ServerRandom: %v", err)
	}

	recordBytes := []byte("test-record-bytes-for-auth")

	tag1, err := deriver.AuthTag(serverRandom, recordBytes, DefaultTagLen)
	if err != nil {
		t.Fatalf("AuthTag failed: %v", err)
	}
	if len(tag1) != DefaultTagLen {
		t.Errorf("Tag length = %d, want %d", len(tag1), DefaultTagLen)
	}

	// Same inputs → same tag
	tag2, err := deriver.AuthTag(serverRandom, recordBytes, DefaultTagLen)
	if err != nil {
		t.Fatalf("AuthTag second call failed: %v", err)
	}
	if !bytes.Equal(tag1, tag2) {
		t.Error("AuthTag not deterministic")
	}

	// Different record bytes → different tag
	tag3, err := deriver.AuthTag(serverRandom, []byte("different-record"), DefaultTagLen)
	if err != nil {
		t.Fatalf("AuthTag with different record failed: %v", err)
	}
	if bytes.Equal(tag1, tag3) {
		t.Error("Different record bytes produced same tag")
	}
}

func TestDeriver_VerifyAuthTag(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		t.Fatalf("Failed to generate PSK: %v", err)
	}

	deriver := NewDeriver(psk)

	serverRandom := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		t.Fatalf("Failed to generate ServerRandom: %v", err)
	}

	recordBytes := []byte("test-record-bytes")

	tag, err := deriver.AuthTag(serverRandom, recordBytes, DefaultTagLen)
	if err != nil {
		t.Fatalf("AuthTag failed: %v", err)
	}

	// Verify with correct tag
	ok, err := deriver.VerifyAuthTag(serverRandom, recordBytes, tag)
	if err != nil {
		t.Fatalf("VerifyAuthTag failed: %v", err)
	}
	if !ok {
		t.Error("VerifyAuthTag returned false for valid tag")
	}

	// Verify with wrong tag
	wrongTag := make([]byte, len(tag))
	copy(wrongTag, tag)
	wrongTag[0] ^= 0xFF

	ok, err = deriver.VerifyAuthTag(serverRandom, recordBytes, wrongTag)
	if err != nil {
		t.Fatalf("VerifyAuthTag with wrong tag failed: %v", err)
	}
	if ok {
		t.Error("VerifyAuthTag returned true for invalid tag")
	}

	// Verify with wrong PSK
	differentDeriver := NewDeriver([]byte("different-psk-12345678"))
	ok, err = differentDeriver.VerifyAuthTag(serverRandom, recordBytes, tag)
	if err != nil {
		t.Fatalf("VerifyAuthTag with wrong PSK failed: %v", err)
	}
	if ok {
		t.Error("VerifyAuthTag returned true for tag from different PSK")
	}
}

func TestDeriver_DeriveDirectionalKeys(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		t.Fatalf("Failed to generate PSK: %v", err)
	}

	deriver := NewDeriver(psk)

	serverRandom := make([]byte, 32)
	clientRandom := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		t.Fatalf("Failed to generate ServerRandom: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, clientRandom); err != nil {
		t.Fatalf("Failed to generate ClientRandom: %v", err)
	}

	sendKey, recvKey, err := deriver.DeriveDirectionalKeys(serverRandom, clientRandom)
	if err != nil {
		t.Fatalf("DeriveDirectionalKeys failed: %v", err)
	}
	if len(sendKey) != DefaultKeyLen {
		t.Errorf("Send key length = %d, want %d", len(sendKey), DefaultKeyLen)
	}
	if len(recvKey) != DefaultKeyLen {
		t.Errorf("Recv key length = %d, want %d", len(recvKey), DefaultKeyLen)
	}
	if bytes.Equal(sendKey, recvKey) {
		t.Error("Send and receive keys should be different")
	}
}

func TestNewDeriverFromHex(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		t.Fatalf("Failed to generate PSK: %v", err)
	}

	pskHex := hex.EncodeToString(psk)
	deriver, err := NewDeriverFromHex(pskHex)
	if err != nil {
		t.Fatalf("NewDeriverFromHex failed: %v", err)
	}

	serverRandom := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		t.Fatalf("Failed to generate ServerRandom: %v", err)
	}

	kAuth, err := deriver.DeriveAuthKey(serverRandom)
	if err != nil {
		t.Fatalf("DeriveAuthKey failed: %v", err)
	}
	if len(kAuth) != DefaultKeyLen {
		t.Errorf("K_auth length = %d, want %d", len(kAuth), DefaultKeyLen)
	}
}

func TestNewDeriverFromHex_InvalidHex(t *testing.T) {
	_, err := NewDeriverFromHex("not-valid-hex!!!")
	if err == nil {
		t.Error("Expected error for invalid hex, got nil")
	}
}

func BenchmarkDeriveAuthKey(b *testing.B) {
	psk := make([]byte, 32)
	io.ReadFull(rand.Reader, psk)
	deriver := NewDeriver(psk)
	serverRandom := make([]byte, 32)
	io.ReadFull(rand.Reader, serverRandom)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deriver.DeriveAuthKey(serverRandom)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveSessionKey(b *testing.B) {
	psk := make([]byte, 32)
	io.ReadFull(rand.Reader, psk)
	deriver := NewDeriver(psk)
	serverRandom := make([]byte, 32)
	clientRandom := make([]byte, 32)
	io.ReadFull(rand.Reader, serverRandom)
	io.ReadFull(rand.Reader, clientRandom)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deriver.DeriveSessionKey(serverRandom, clientRandom)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthTag(b *testing.B) {
	psk := make([]byte, 32)
	io.ReadFull(rand.Reader, psk)
	deriver := NewDeriver(psk)
	serverRandom := make([]byte, 32)
	io.ReadFull(rand.Reader, serverRandom)
	recordBytes := make([]byte, 1024)
	io.ReadFull(rand.Reader, recordBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deriver.AuthTag(serverRandom, recordBytes, DefaultTagLen)
		if err != nil {
			b.Fatal(err)
		}
	}
}
