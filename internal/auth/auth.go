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
	"sync"

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

// UserEntry associates a user identifier with a pre-derived key deriver.
type UserEntry struct {
	UserID  string
	Deriver *keyderiv.Deriver
}

// UserStore manages authentication for multiple users, each identified by a
// 4-byte hint derived from their user ID. The relay uses the hint from the
// auth frame to look up the correct PSK for tag verification.
type UserStore struct {
	mu     sync.RWMutex
	byHint map[[4]byte]*UserEntry
	tagLen int
}

// NewUserStore creates a UserStore from a map of userID → pskHex.
// The key hint is computed as SHA256(userID)[:4].
func NewUserStore(users map[string]string, tagLen int) (*UserStore, error) {
	if tagLen < MinTagLen || tagLen > MaxTagLen {
		return nil, fmt.Errorf("%w: %d", ErrInvalidTagLen, tagLen)
	}
	if len(users) == 0 {
		return nil, errors.New("auth: at least one user is required")
	}

	store := &UserStore{
		byHint: make(map[[4]byte]*UserEntry, len(users)),
		tagLen: tagLen,
	}

	for userID, pskHex := range users {
		psk, err := hex.DecodeString(pskHex)
		if err != nil {
			return nil, fmt.Errorf("auth: invalid PSK for user %q: %w", userID, err)
		}
		hint := keyderiv.ComputeKeyHint(userID)
		if _, exists := store.byHint[hint]; exists {
			return nil, fmt.Errorf("auth: key hint collision for user %q (hint %x already taken)", userID, hint)
		}
		store.byHint[hint] = &UserEntry{
			UserID:  userID,
			Deriver: keyderiv.NewDeriver(psk),
		}
	}

	return store, nil
}

// DerivePSKFromID derives a 256-bit PSK from a user identifier.
// PSK = SHA256(userID). This allows relay deployment with only a UUID list,
// since the same derivation happens on the client side.
func DerivePSKFromID(userID string) []byte {
	h := sha256.Sum256([]byte(userID))
	return h[:]
}

// NewUserStoreFromIDs creates a UserStore from a list of user identifiers.
// Each user's PSK is derived as PSK = SHA256(userID).
// This is the recommended constructor for multi-user deployments where
// UUIDs serve as both identifier and key material.
func NewUserStoreFromIDs(userIDs []string, tagLen int) (*UserStore, error) {
	users := make(map[string]string, len(userIDs))
	for _, id := range userIDs {
		users[id] = hex.EncodeToString(DerivePSKFromID(id))
	}
	return NewUserStore(users, tagLen)
}

// KeyHint returns the 4-byte hint for a given user identifier.
func (s *UserStore) KeyHint(userID string) [4]byte {
	return keyderiv.ComputeKeyHint(userID)
}

// TagLen returns the configured tag length.
func (s *UserStore) TagLen() int {
	return s.tagLen
}

// lookup returns the entry for a given hint, or nil.
// Caller must hold s.mu (read or write lock).
func (s *UserStore) lookup(hint [4]byte) *UserEntry {
	return s.byHint[hint]
}

// GenerateTag computes the auth tag for a user identified by hint.
func (s *UserStore) GenerateTag(hint [4]byte, serverRandom, recordBytes []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry := s.lookup(hint)
	if entry == nil {
		return nil, fmt.Errorf("auth: unknown key hint %x", hint)
	}
	if len(serverRandom) != 32 {
		return nil, ErrServerRandomLength
	}
	if len(recordBytes) == 0 {
		return nil, ErrRecordBytesEmpty
	}
	return entry.Deriver.AuthTag(serverRandom, recordBytes, s.tagLen)
}

// VerifyTag verifies an auth tag for a user identified by hint.
func (s *UserStore) VerifyTag(hint [4]byte, serverRandom, recordBytes, tag []byte) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry := s.lookup(hint)
	if entry == nil {
		return false, fmt.Errorf("auth: unknown key hint %x", hint)
	}
	if len(tag) != s.tagLen {
		return false, fmt.Errorf("auth: tag length mismatch: got %d, want %d", len(tag), s.tagLen)
	}
	return entry.Deriver.VerifyAuthTag(serverRandom, recordBytes, tag)
}

// AddUser adds or replaces a user at runtime. Thread-safe.
// If pskHex is empty, PSK is derived as SHA256(userID).
// If a user with the same hint already exists, it is replaced.
func (s *UserStore) AddUser(userID, pskHex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pskHex == "" {
		pskHex = hex.EncodeToString(DerivePSKFromID(userID))
	}
	psk, err := hex.DecodeString(pskHex)
	if err != nil {
		return fmt.Errorf("auth: invalid PSK for user %q: %w", userID, err)
	}

	hint := keyderiv.ComputeKeyHint(userID)
	s.byHint[hint] = &UserEntry{
		UserID:  userID,
		Deriver: keyderiv.NewDeriver(psk),
	}
	return nil
}

// RemoveUserByID removes a user by their original user identifier. Thread-safe.
// Returns an error if the user is not found.
func (s *UserStore) RemoveUserByID(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hint := keyderiv.ComputeKeyHint(userID)
	if _, ok := s.byHint[hint]; !ok {
		return fmt.Errorf("auth: user %q not found (hint %x)", userID, hint)
	}
	delete(s.byHint, hint)
	return nil
}

// ListUserIDs returns all currently registered user identifiers. Thread-safe.
func (s *UserStore) ListUserIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.byHint))
	for _, entry := range s.byHint {
		ids = append(ids, entry.UserID)
	}
	return ids
}

// Count returns the number of registered users. Thread-safe.
func (s *UserStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byHint)
}

// ExtractKeyHint extracts the 4-byte key hint from the auth frame payload.
// The hint is the first 4 bytes of the payload.
func ExtractKeyHint(payload []byte) ([4]byte, error) {
	var hint [4]byte
	if len(payload) < 4 {
		return hint, errors.New("auth: payload too short for key hint (need 4 bytes)")
	}
	copy(hint[:], payload[:4])
	return hint, nil
}

// ExtractTagFromHintFrame extracts the auth tag from a payload that includes
// the 4-byte key hint prefix. Returns the tag bytes after the hint.
func ExtractTagFromHintFrame(payload []byte, tagLen int) ([]byte, error) {
	if len(payload) < 4+tagLen {
		return nil, fmt.Errorf("auth: payload too short for hint frame (got %d, need %d)", len(payload), 4+tagLen)
	}
	tag := make([]byte, tagLen)
	copy(tag, payload[4:4+tagLen])
	return tag, nil
}
