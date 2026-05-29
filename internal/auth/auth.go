// Package auth implements the covert authentication mechanism (Part II §8).
//
// The authentication is based on a shared PSK and uses HMAC-SHA256 over
// observable record bytes. The auth tag is embedded in the first
// application_data record after the TLS handshake.
//
//	K_auth = HKDF(PSK, label="chimney-auth", info = ServerRandom)
//	tag = HMAC(K_auth, ServerRandom || <observable bytes of the record>)[:TAG_LEN]
//
// Key properties:
//   - ServerRandom is plaintext in TLS 1.3 ServerHello, so the relay can
//     observe it during forwarding without needing the TLS session key.
//   - The tag is indistinguishable from random ciphertext to observers
//     without the PSK.
//   - Each session has a unique tag (bound to ServerRandom), preventing replay.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/shuffleman/chimney-protocol/internal/keyderiv"
)

const (
	// DefaultTagLen is the default authentication tag length (16 bytes).
	DefaultTagLen = keyderiv.DefaultTagLen

	// MinTagLen is the minimum recommended tag length (8 bytes per spec).
	MinTagLen = 8

	// MaxTagLen is the maximum tag length (SHA-256 output size).
	MaxTagLen = sha256.Size
)

var (
	// ErrInvalidTagLen is returned when the tag length is out of range.
	ErrInvalidTagLen = errors.New("auth: invalid tag length")

	// ErrServerRandomLength is returned when ServerRandom is not 32 bytes.
	ErrServerRandomLength = errors.New("auth: ServerRandom must be 32 bytes")

	// ErrRecordBytesEmpty is returned when record bytes are empty.
	ErrRecordBytesEmpty = errors.New("auth: record bytes cannot be empty")

	// ErrAuthFailed is returned when authentication verification fails.
	ErrAuthFailed = errors.New("auth: authentication failed")
)

// Authenticator handles covert authentication for the Chimney protocol.
type Authenticator struct {
	deriver *keyderiv.Deriver
	tagLen  int
}

// NewAuthenticator creates a new authenticator from a raw PSK.
func NewAuthenticator(psk []byte, tagLen int) (*Authenticator, error) {
	if tagLen < MinTagLen || tagLen > MaxTagLen {
		return nil, fmt.Errorf("%w: %d (must be %d-%d)", ErrInvalidTagLen, tagLen, MinTagLen, MaxTagLen)
	}
	return &Authenticator{
		deriver: keyderiv.NewDeriver(psk),
		tagLen:  tagLen,
	}, nil
}

// NewAuthenticatorFromHex creates a new authenticator from a hex-encoded PSK.
func NewAuthenticatorFromHex(pskHex string, tagLen int) (*Authenticator, error) {
	psk, err := hex.DecodeString(pskHex)
	if err != nil {
		return nil, fmt.Errorf("auth: invalid PSK hex: %w", err)
	}
	return NewAuthenticator(psk, tagLen)
}

// GenerateTag computes the authentication tag for the first application_data record.
//
// serverRandom: 32 bytes from ServerHello.random (observed during handshake forwarding).
// recordBytes: the complete on-the-wire bytes of the first application_data record
// (5-byte header + ciphertext). This is what the relay can observe.
//
// Returns the tag (tagLen bytes) and any error.
func (a *Authenticator) GenerateTag(serverRandom, recordBytes []byte) ([]byte, error) {
	if len(serverRandom) != 32 {
		return nil, ErrServerRandomLength
	}
	if len(recordBytes) == 0 {
		return nil, ErrRecordBytesEmpty
	}

	return a.deriver.AuthTag(serverRandom, recordBytes, a.tagLen)
}

// VerifyTag verifies an authentication tag.
//
// Returns true if the tag is valid (holder has the PSK), false otherwise.
// This operation uses constant-time comparison to prevent timing attacks.
func (a *Authenticator) VerifyTag(serverRandom, recordBytes, tag []byte) (bool, error) {
	if len(serverRandom) != 32 {
		return false, ErrServerRandomLength
	}
	if len(recordBytes) == 0 {
		return false, ErrRecordBytesEmpty
	}
	if len(tag) != a.tagLen {
		return false, fmt.Errorf("auth: tag length mismatch: got %d, want %d", len(tag), a.tagLen)
	}

	return a.deriver.VerifyAuthTag(serverRandom, recordBytes, tag)
}

// MustVerifyTag is like VerifyTag but returns ErrAuthFailed on verification failure
// instead of (false, nil).
func (a *Authenticator) MustVerifyTag(serverRandom, recordBytes, tag []byte) error {
	ok, err := a.VerifyTag(serverRandom, recordBytes, tag)
	if err != nil {
		return err
	}
	if !ok {
		return ErrAuthFailed
	}
	return nil
}

// TagLen returns the configured tag length.
func (a *Authenticator) TagLen() int {
	return a.tagLen
}

// EmbedTagLocation describes where in the first application_data record
// the auth tag should be embedded.
//
// The tag is embedded at a fixed offset within the encrypted payload.
// Both client and relay know this offset from the protocol specification.
// The offset must be large enough to accommodate the tag but not so large
// that it exceeds typical first-record sizes.
type EmbedTagLocation struct {
	// PayloadOffset is the byte offset within the AEAD plaintext payload
	// where the tag starts.
	PayloadOffset int

	// TagLen is the length of the tag in bytes.
	TagLen int
}

// DefaultEmbedLocation is the default tag embedding location.
// The tag is placed at offset 0 within the first application_data record's
// plaintext payload. This means the first bytes of the H2 frame stream
// (after decryption) contain the auth tag.
//
// In practice, the client sends the first application_data record containing:
//   - The auth tag at the beginning of the payload
//   - H2 preface + SETTINGS following the tag
//
// The relay extracts the tag, verifies it, and if valid, processes the
// remaining payload as the start of the H2 stream.
var DefaultEmbedLocation = EmbedTagLocation{
	PayloadOffset: 0,
	TagLen:        DefaultTagLen,
}

// ExtractTag extracts the auth tag from the decrypted payload of the first
// application_data record.
func ExtractTag(payload []byte, loc EmbedTagLocation) ([]byte, []byte, error) {
	if loc.PayloadOffset+loc.TagLen > len(payload) {
		return nil, nil, errors.New("auth: payload too short for tag extraction")
	}
	tag := payload[loc.PayloadOffset : loc.PayloadOffset+loc.TagLen]
	remaining := append(payload[:loc.PayloadOffset], payload[loc.PayloadOffset+loc.TagLen:]...)
	return tag, remaining, nil
}

// EmbedTag embeds the auth tag into a payload at the specified location.
func EmbedTag(payload []byte, tag []byte, loc EmbedTagLocation) []byte {
	result := make([]byte, 0, loc.PayloadOffset+len(tag)+len(payload)-loc.PayloadOffset)
	result = append(result, payload[:loc.PayloadOffset]...)
	result = append(result, tag...)
	result = append(result, payload[loc.PayloadOffset:]...)
	return result
}

// ServerRandomExtractor extracts ServerRandom from a TLS 1.3 ServerHello message.
// This is used by the relay to obtain ServerRandom during pure TCP forwarding
// without decrypting the TLS handshake.
//
// ServerHello structure (simplified, TLS 1.3):
//
//	struct {
//	    HandshakeType msg_type;     // 1 byte = 0x02 for ServerHello
//	    uint24 length;
//	    ProtocolVersion version;    // 2 bytes = 0x0303
//	    Random random;              // 32 bytes  <-- THIS IS WHAT WE WANT
//	    ...
//	}
//
// Note: This operates on the raw handshake bytes as seen on the wire during
// TCP forwarding. The relay observes these bytes in plaintext because TLS 1.3
// encrypts only after the ServerHello.
type ServerRandomExtractor struct{}

// ExtractFromServerHello extracts the 32-byte ServerRandom from a TLS ServerHello.
// The data should start with the ServerHello handshake message.
//
// Returns the ServerRandom and any error.
func (e *ServerRandomExtractor) ExtractFromServerHello(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, errors.New("auth: insufficient data for ServerHello header")
	}

	msgType := data[0]
	if msgType != 0x02 {
		return nil, fmt.Errorf("auth: expected ServerHello (0x02), got 0x%02x", msgType)
	}

	// length is 3 bytes
	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if len(data) < 4+int(length) {
		return nil, errors.New("auth: ServerHello data shorter than length indicates")
	}

	body := data[4 : 4+length]

	// Parse ServerHello body:
	// version (2) + random (32) + session_id_len (1) + session_id + ...
	if len(body) < 2+32 {
		return nil, errors.New("auth: ServerHello body too short")
	}

	version := uint16(body[0])<<8 | uint16(body[1])
	if version != 0x0303 {
		// TLS 1.3 uses 0x0303 in ServerHello for compatibility
		// but we allow other versions for flexibility
		_ = version
	}

	serverRandom := make([]byte, 32)
	copy(serverRandom, body[2:34])

	return serverRandom, nil
}

// ExtractFromHandshakeMessages scans through a sequence of TLS handshake
// messages and extracts ServerRandom from the first ServerHello found.
// This is useful when the relay has buffered multiple handshake messages.
func (e *ServerRandomExtractor) ExtractFromHandshakeMessages(data []byte) ([]byte, error) {
	offset := 0
	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}

		msgType := data[offset]
		msgLen := int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])

		if msgType == 0x02 { // ServerHello
			return e.ExtractFromServerHello(data[offset:])
		}

		offset += 4 + msgLen
	}

	return nil, errors.New("auth: no ServerHello found in handshake messages")
}

// ExtractFromTLSRecords parses raw TLS record bytes (as seen on the wire during
// TCP forwarding), strips the 5-byte TLS record headers from Handshake records
// (ContentType=0x16), and feeds the concatenated handshake message payloads to
// ExtractFromHandshakeMessages.
//
// This is the method the relay should use during blind TCP forwarding, since
// the relay sees TLS records, not bare handshake messages.
//
// TLS record format:
//
//	struct {
//	    ContentType type;      // 1 byte
//	    ProtocolVersion version; // 2 bytes
//	    uint16 length;         // 2 bytes
//	    opaque fragment[length];
//	} TLSRecord;
func (e *ServerRandomExtractor) ExtractFromTLSRecords(data []byte) ([]byte, error) {
	var handshakeMsgs []byte
	offset := 0
	for offset+5 <= len(data) {
		contentType := data[offset]
		recordLen := int(data[offset+3])<<8 | int(data[offset+4])

		if offset+5+recordLen > len(data) {
			break // incomplete record
		}

		if contentType == 0x16 { // Handshake
			handshakeMsgs = append(handshakeMsgs, data[offset+5:offset+5+recordLen]...)
		}

		offset += 5 + recordLen
	}

	if len(handshakeMsgs) == 0 {
		return nil, errors.New("auth: no Handshake records found in TLS data")
	}

	return e.ExtractFromHandshakeMessages(handshakeMsgs)
}

// ClientRandomExtractor extracts ClientRandom from a TLS ClientHello.
type ClientRandomExtractor struct{}

// ExtractFromClientHello extracts the 32-byte ClientRandom from a TLS ClientHello.
func (e *ClientRandomExtractor) ExtractFromClientHello(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, errors.New("auth: insufficient data for ClientHello header")
	}

	msgType := data[0]
	if msgType != 0x01 {
		return nil, fmt.Errorf("auth: expected ClientHello (0x01), got 0x%02x", msgType)
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if len(data) < 4+int(length) {
		return nil, errors.New("auth: ClientHello data shorter than length indicates")
	}

	body := data[4 : 4+length]
	if len(body) < 2+32 {
		return nil, errors.New("auth: ClientHello body too short")
	}

	clientRandom := make([]byte, 32)
	copy(clientRandom, body[2:34])

	return clientRandom, nil
}

// RecordBytesCollector collects the observable bytes of the first application_data
// record for auth tag computation/verification.
//
// The "observable bytes" are the complete on-the-wire bytes of the record:
// the 5-byte header (type || version || length) followed by the ciphertext.
// These are exactly the bytes the relay sees during TCP forwarding.
type RecordBytesCollector struct {
	buf []byte
}

// NewRecordBytesCollector creates a new collector.
func NewRecordBytesCollector() *RecordBytesCollector {
	return &RecordBytesCollector{buf: make([]byte, 0, 4096)}
}

// Write appends data to the collector.
func (rc *RecordBytesCollector) Write(p []byte) (int, error) {
	rc.buf = append(rc.buf, p...)
	return len(p), nil
}

// Bytes returns the collected bytes.
func (rc *RecordBytesCollector) Bytes() []byte {
	return rc.buf
}

// Reset clears the collector.
func (rc *RecordBytesCollector) Reset() {
	rc.buf = rc.buf[:0]
}
