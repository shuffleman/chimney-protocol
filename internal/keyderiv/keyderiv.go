// Package keyderiv implements HKDF-based key derivation per Part II §8 and §9.
//
// Authentication key:
//
//	K_auth = HKDF(PSK, label="chimney-auth", info = ServerRandom)
//
// Session key:
//
//	K_sess = HKDF(PSK, label="chimney-sess", info = ServerRandom || ClientRandom)
//
// Current auth tag:
//
//	tag = HMAC(K_auth, ServerRandom || ClientRandom)[:TAG_LEN]
//
// The parameter is still named recordBytes in the lower-level helper for
// compatibility with older tests and the original design, but current client
// and relay paths pass ClientRandom as that second HMAC input.
package keyderiv

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// LabelAuth is the HKDF label for the authentication key.
	LabelAuth = "chimney-auth"

	// LabelSess is the HKDF label for the session key.
	LabelSess = "chimney-sess"

	// DefaultTagLen is the default auth tag length in bytes.
	// The spec recommends 8-16 bytes; we use 16 for strong security.
	DefaultTagLen = 16

	// DefaultKeyLen is the default derived key length (32 bytes = 256 bits).
	DefaultKeyLen = 32

	// DefaultNonceBaseLen is the default nonce base length (12 bytes for GCM/ChaCha20).
	DefaultNonceBaseLen = 12
)

// Deriver holds the PSK and provides key derivation methods.
type Deriver struct {
	psk []byte
}

// NewDeriver creates a new key deriver from a PSK.
func NewDeriver(psk []byte) *Deriver {
	pskCopy := make([]byte, len(psk))
	copy(pskCopy, psk)
	return &Deriver{psk: pskCopy}
}

// NewDeriverFromHex creates a new key deriver from a hex-encoded PSK string.
func NewDeriverFromHex(pskHex string) (*Deriver, error) {
	psk, err := hex.DecodeString(pskHex)
	if err != nil {
		return nil, fmt.Errorf("keyderiv: invalid PSK hex: %w", err)
	}
	if len(psk) != DefaultKeyLen {
		return nil, fmt.Errorf("keyderiv: invalid PSK length: got %d bytes, want %d", len(psk), DefaultKeyLen)
	}
	return NewDeriver(psk), nil
}

// GeneratePSK generates a random PSK of the specified length.
func GeneratePSK(length int) ([]byte, error) {
	psk := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		return nil, fmt.Errorf("keyderiv: failed to generate PSK: %w", err)
	}
	return psk, nil
}

// deriveKey derives a key using HKDF-SHA256.
func (d *Deriver) deriveKey(label string, info []byte, keyLen int) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, d.psk, []byte(label), info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("keyderiv: HKDF extract failed for label %q: %w", label, err)
	}
	return key, nil
}

// DeriveAuthKey derives K_auth = HKDF(PSK, label="chimney-auth", info=ServerRandom).
//
// ServerRandom is 32 bytes from the TLS ServerHello.random field.
func (d *Deriver) DeriveAuthKey(serverRandom []byte) ([]byte, error) {
	if len(serverRandom) != 32 {
		return nil, fmt.Errorf("keyderiv: ServerRandom must be 32 bytes, got %d", len(serverRandom))
	}
	return d.deriveKey(LabelAuth, serverRandom, DefaultKeyLen)
}

// DeriveSessionKey derives K_sess = HKDF(PSK, label="chimney-sess", info=ServerRandom||ClientRandom).
//
// Both ServerRandom and ClientRandom are 32 bytes each.
func (d *Deriver) DeriveSessionKey(serverRandom, clientRandom []byte) ([]byte, error) {
	if len(serverRandom) != 32 {
		return nil, fmt.Errorf("keyderiv: ServerRandom must be 32 bytes, got %d", len(serverRandom))
	}
	if len(clientRandom) != 32 {
		return nil, fmt.Errorf("keyderiv: ClientRandom must be 32 bytes, got %d", len(clientRandom))
	}
	info := make([]byte, 64)
	copy(info, serverRandom)
	copy(info[32:], clientRandom)
	return d.deriveKey(LabelSess, info, DefaultKeyLen)
}

// DeriveNonceBase derives a nonce base for AEAD from the session key material.
// Uses HKDF with a distinct label to ensure separation from encryption keys.
func (d *Deriver) DeriveNonceBase(serverRandom, clientRandom []byte) ([]byte, error) {
	info := make([]byte, 64)
	copy(info, serverRandom)
	copy(info[32:], clientRandom)
	return d.deriveKey("chimney-nonce", info, DefaultNonceBaseLen)
}

// DeriveDirectionalKeys derives separate send and receive keys for client-relay communication.
//
// For client→relay: label="chimney-sess-send"
// For relay→client: label="chimney-sess-recv"
func (d *Deriver) DeriveDirectionalKeys(serverRandom, clientRandom []byte) (sendKey, recvKey []byte, err error) {
	if len(serverRandom) != 32 || len(clientRandom) != 32 {
		return nil, nil, fmt.Errorf("keyderiv: randoms must be 32 bytes each")
	}
	info := make([]byte, 64)
	copy(info, serverRandom)
	copy(info[32:], clientRandom)

	sendKey, err = d.deriveKey("chimney-sess-send", info, DefaultKeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("keyderiv: failed to derive send key: %w", err)
	}

	recvKey, err = d.deriveKey("chimney-sess-recv", info, DefaultKeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("keyderiv: failed to derive recv key: %w", err)
	}

	return sendKey, recvKey, nil
}

// AuthTag computes the authentication tag over caller-provided context bytes:
//
//	tag = HMAC-SHA256(K_auth, ServerRandom || recordBytes)[:tagLen]
//
// K_auth is derived internally from PSK and ServerRandom.
// In the current protocol implementation, recordBytes is ClientRandom. Older
// tests and helpers still use this generic name because the first design used
// observable TLS record bytes as the second HMAC input.
func (d *Deriver) AuthTag(serverRandom, recordBytes []byte, tagLen int) ([]byte, error) {
	kAuth, err := d.DeriveAuthKey(serverRandom)
	if err != nil {
		return nil, fmt.Errorf("keyderiv: failed to derive auth key: %w", err)
	}

	mac := hmac.New(sha256.New, kAuth)
	mac.Write(serverRandom)
	mac.Write(recordBytes)
	tag := mac.Sum(nil)

	if tagLen > len(tag) {
		tagLen = len(tag)
	}
	return tag[:tagLen], nil
}

// VerifyAuthTag verifies an auth tag matches the expected value.
// Uses constant-time comparison to prevent timing attacks.
func (d *Deriver) VerifyAuthTag(serverRandom, recordBytes, tag []byte) (bool, error) {
	expected, err := d.AuthTag(serverRandom, recordBytes, len(tag))
	if err != nil {
		return false, err
	}
	return hmac.Equal(expected, tag), nil
}

// ComputeKeyHint returns a 4-byte hint derived from a user identifier.
// The hint is SHA256(userID)[:4] and is used by the relay to look up
// the correct PSK for multi-user authentication.
func ComputeKeyHint(userID string) [4]byte {
	h := sha256.Sum256([]byte(userID))
	var hint [4]byte
	copy(hint[:], h[:4])
	return hint
}
