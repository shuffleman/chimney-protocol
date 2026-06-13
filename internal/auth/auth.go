// Package auth 实现隐蔽认证机制（Part II §8）。
//
// 认证基于共享的 PSK，使用 HMAC-SHA256 基于
// TLS ServerRandom 和 ClientRandom（在借用的握手过程中观察到）进行计算。
// 当前协议在 ChimneyRecord/H2 开启序列之后将认证标签作为 H2 DATA 帧发送。
//
//	K_auth = HKDF(PSK, label="chimney-auth", info = ServerRandom)
//	tag = HMAC(K_auth, ServerRandom || ClientRandom)[:TAG_LEN]
//
// 关键特性：
//   - ServerRandom 在 TLS 1.3 ServerHello 中是明文的，因此中继可以在
//     转发过程中观察到它，无需 TLS 会话密钥。
//   - 没有 PSK 的观察者无法将标签与随机密文区分。
//   - 每个会话都有唯一标签（绑定到 ServerRandom），防止重放。
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
	// DefaultTagLen 是默认认证标签长度（16 字节）。
	DefaultTagLen = keyderiv.DefaultTagLen

	// MinTagLen 是最小推荐标签长度（规范要求 8 字节）。
	MinTagLen = 8

	// MaxTagLen 是最大标签长度（SHA-256 输出大小）。
	MaxTagLen = sha256.Size
)

var (
	// ErrInvalidTagLen 标签长度超出范围时返回。
	ErrInvalidTagLen = errors.New("auth: invalid tag length")

	// ErrServerRandomLength 当 ServerRandom 不是 32 字节时返回。
	ErrServerRandomLength = errors.New("auth: ServerRandom must be 32 bytes")

	// ErrRecordBytesEmpty 当记录字节为空时返回。
	ErrRecordBytesEmpty = errors.New("auth: record bytes cannot be empty")

	// ErrAuthFailed 认证验证失败时返回。
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
	if len(psk) != keyderiv.DefaultKeyLen {
		return nil, fmt.Errorf("auth: invalid PSK length: got %d bytes, want %d", len(psk), keyderiv.DefaultKeyLen)
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

// GenerateTag computes an authentication tag.
//
// serverRandom: 32 bytes from ServerHello.random (observed during handshake forwarding).
// recordBytes: generic second HMAC input. In the current protocol, callers pass
// ClientRandom here; the name remains for compatibility with the older design.
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

// TagLen 返回配置的标签长度。
func (a *Authenticator) TagLen() int {
	return a.tagLen
}

// EmbedTagLocation 描述了旧设计中认证标签应嵌入的位置。
// 第一个 application_data 记录。
//
// 标签嵌入在加密负载内的固定偏移处。
// 客户端和中继都知道这个偏移量（来自协议规范）。
// 偏移量必须足够大以容纳标签，但不能太大
// 以至于超过典型的首记录大小。
type EmbedTagLocation struct {
	// PayloadOffset 是 AEAD 明文负载内标签开始的字节偏移。
	PayloadOffset int

	// TagLen 是标签的字节长度。
	TagLen int
}

// DefaultEmbedLocation 是旧的 pre-H2-auth 设计的默认标签嵌入位置。
// 标签放置在第一个 application_data 记录的明文负载的偏移 0 处。
// 这意味着 H2 帧流（解密后）的第一个字节包含认证标签。
//
// 当前客户端/中继代码在 ChimneyRecord/H2 握手之后将 [key_hint][auth_tag]
// 作为 H2 DATA 帧发送，因此此位置辅助函数仅保留用于测试和旧辅助功能。
var DefaultEmbedLocation = EmbedTagLocation{
	PayloadOffset: 0,
	TagLen:        DefaultTagLen,
}

// ExtractTag 从第一个 application_data 记录的解密负载中提取认证标签。
func ExtractTag(payload []byte, loc EmbedTagLocation) ([]byte, []byte, error) {
	if loc.PayloadOffset+loc.TagLen > len(payload) {
		return nil, nil, errors.New("auth: payload too short for tag extraction")
	}
	tag := payload[loc.PayloadOffset : loc.PayloadOffset+loc.TagLen]
	remaining := append(payload[:loc.PayloadOffset], payload[loc.PayloadOffset+loc.TagLen:]...)
	return tag, remaining, nil
}

// EmbedTag 将认证标签嵌入到指定位置的负载中。
func EmbedTag(payload []byte, tag []byte, loc EmbedTagLocation) []byte {
	result := make([]byte, 0, loc.PayloadOffset+len(tag)+len(payload)-loc.PayloadOffset)
	result = append(result, payload[:loc.PayloadOffset]...)
	result = append(result, tag...)
	result = append(result, payload[loc.PayloadOffset:]...)
	return result
}

// ServerRandomExtractor 从 TLS 1.3 ServerHello 消息中提取 ServerRandom。
// 中继在纯 TCP 转发期间使用它来获取 ServerRandom，
// 而无需解密 TLS 握手。
//
// ServerHello 结构（简化版，TLS 1.3）：
//
//	struct {
//	    HandshakeType msg_type;     // 1 byte = 0x02 表示 ServerHello
//	    uint24 length;
//	    ProtocolVersion version;    // 2 bytes = 0x0303
//	    Random random;              // 32 bytes  <-- 这才是我们要的
//	    ...
//	}
//
// 注意：此操作针对 TCP 转发期间线路上看到的原始握手字节。
// 中继以明文形式观察到这些字节，因为 TLS 1.3 仅在 ServerHello 之后加密。
type ServerRandomExtractor struct{}

// ExtractFromServerHello 从 TLS ServerHello 中提取 32 字节的 ServerRandom。
// 数据应以 ServerHello 握手消息开头。
//
// 返回 ServerRandom 和可能的错误。
func (e *ServerRandomExtractor) ExtractFromServerHello(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, errors.New("auth: insufficient data for ServerHello header")
	}

	msgType := data[0]
	if msgType != 0x02 {
		return nil, fmt.Errorf("auth: expected ServerHello (0x02), got 0x%02x", msgType)
	}

	// length 是 3 字节
	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if len(data) < 4+int(length) {
		return nil, errors.New("auth: ServerHello data shorter than length indicates")
	}

	body := data[4 : 4+length]

	// 解析 ServerHello 体：
	// version (2) + random (32) + session_id_len (1) + session_id + ...
	if len(body) < 2+32 {
		return nil, errors.New("auth: ServerHello body too short")
	}

	version := uint16(body[0])<<8 | uint16(body[1])
	if version != 0x0303 {
		// TLS 1.3 在 ServerHello 中使用 0x0303 以保持兼容性
		// 但我们允许其他版本以保持灵活性
		_ = version
	}

	serverRandom := make([]byte, 32)
	copy(serverRandom, body[2:34])

	return serverRandom, nil
}

// ExtractFromHandshakeMessages 扫描一系列 TLS 握手消息，
// 并从找到的第一个 ServerHello 中提取 ServerRandom。
// 当中继已缓冲多条握手消息时，这很有用。
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

// ExtractFromTLSRecords 解析原始 TLS 记录字节（TCP 转发期间在线路上看到的），
// 从 Handshake 记录（ContentType=0x16）中剥离 5 字节的 TLS 记录头，
// 并将拼接后的握手消息负载传给 ExtractFromHandshakeMessages。
//
// 这是中继在盲目 TCP 转发期间应使用的方法，因为
// 中继看到的是 TLS 记录，而不是原始的握手消息。
//
// TLS 记录格式：
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
			break // 不完整的记录
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

// ClientRandomExtractor 从 TLS ClientHello 中提取 ClientRandom。
type ClientRandomExtractor struct{}

// ExtractFromClientHello 从 TLS ClientHello 中提取 32 字节的 ClientRandom。
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

// RecordBytesCollector 为旧的首次记录认证标签设计收集可观测字节。
//
// 在旧设计中，这些字节是完整的在线记录：
// 5 字节头（type || version || length）后跟密文。
type RecordBytesCollector struct {
	buf []byte
}

// NewRecordBytesCollector 创建一个新的收集器。
func NewRecordBytesCollector() *RecordBytesCollector {
	return &RecordBytesCollector{buf: make([]byte, 0, 4096)}
}

// Write 将数据追加到收集器。
func (rc *RecordBytesCollector) Write(p []byte) (int, error) {
	rc.buf = append(rc.buf, p...)
	return len(p), nil
}

// Bytes 返回收集到的字节。
func (rc *RecordBytesCollector) Bytes() []byte {
	return rc.buf
}

// Reset 清空收集器。
func (rc *RecordBytesCollector) Reset() {
	rc.buf = rc.buf[:0]
}

// UserEntry 将用户标识符与预派生的密钥派生器关联。
type UserEntry struct {
	UserID  string
	Deriver *keyderiv.Deriver
}

// UserStore 管理多用户的认证，每个用户通过从其用户 ID 派生的
// 4 字节提示标识。提示只用于缩小候选集合；大用户量部署下允许同一 hint
// 命中多个用户，最终仍通过认证标签确认具体密钥。
type UserStore struct {
	mu     sync.RWMutex
	byHint map[[4]byte][]*UserEntry
	tagLen int
}

// NewUserStore 从 userID → pskHex 的映射创建 UserStore。
// 密钥提示计算为 SHA256(userID)[:4]。
func NewUserStore(users map[string]string, tagLen int) (*UserStore, error) {
	if tagLen < MinTagLen || tagLen > MaxTagLen {
		return nil, fmt.Errorf("%w: %d", ErrInvalidTagLen, tagLen)
	}
	if len(users) == 0 {
		return nil, errors.New("auth: at least one user is required")
	}

	store := &UserStore{
		byHint: make(map[[4]byte][]*UserEntry, len(users)),
		tagLen: tagLen,
	}

	for userID, pskHex := range users {
		psk, err := hex.DecodeString(pskHex)
		if err != nil {
			return nil, fmt.Errorf("auth: invalid PSK for user %q: %w", userID, err)
		}
		if len(psk) != keyderiv.DefaultKeyLen {
			return nil, fmt.Errorf("auth: invalid PSK length for user %q: got %d bytes, want %d", userID, len(psk), keyderiv.DefaultKeyLen)
		}
		hint := keyderiv.ComputeKeyHint(userID)
		store.byHint[hint] = append(store.byHint[hint], &UserEntry{
			UserID:  userID,
			Deriver: keyderiv.NewDeriver(psk),
		})
	}

	return store, nil
}

// DerivePSKFromID 从用户标识符派生 256 位 PSK。
// PSK = SHA256(userID)。这允许仅使用 UUID 列表部署中继，
// 因为客户端侧执行相同的派生。
func DerivePSKFromID(userID string) []byte {
	h := sha256.Sum256([]byte(userID))
	return h[:]
}

// NewUserStoreFromIDs 从用户标识符列表创建 UserStore。
// 每个用户的 PSK 派生为 PSK = SHA256(userID)。
// 这是多用户部署的推荐构造函数，其中
// UUID 同时充当标识符和密钥材料。
func NewUserStoreFromIDs(userIDs []string, tagLen int) (*UserStore, error) {
	users := make(map[string]string, len(userIDs))
	for _, id := range userIDs {
		users[id] = hex.EncodeToString(DerivePSKFromID(id))
	}
	return NewUserStore(users, tagLen)
}

// KeyHint 返回给定用户标识符的 4 字节提示。
func (s *UserStore) KeyHint(userID string) [4]byte {
	return keyderiv.ComputeKeyHint(userID)
}

// TagLen 返回配置的标签长度。
func (s *UserStore) TagLen() int {
	return s.tagLen
}

// lookup 返回给定提示的候选条目，如果不存在则返回 nil。
// 调用者必须持有 s.mu（读锁或写锁）。
func (s *UserStore) lookup(hint [4]byte) []*UserEntry {
	return s.byHint[hint]
}

// GenerateTag 计算由 hint 标识的用户的认证标签。
func (s *UserStore) GenerateTag(hint [4]byte, serverRandom, recordBytes []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := s.lookup(hint)
	if len(entries) == 0 {
		return nil, fmt.Errorf("auth: unknown key hint %x", hint)
	}
	if len(serverRandom) != 32 {
		return nil, ErrServerRandomLength
	}
	if len(recordBytes) == 0 {
		return nil, ErrRecordBytesEmpty
	}
	return entries[0].Deriver.AuthTag(serverRandom, recordBytes, s.tagLen)
}

// VerifyTag 验证由 hint 标识的用户的认证标签。
func (s *UserStore) VerifyTag(hint [4]byte, serverRandom, recordBytes, tag []byte) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := s.lookup(hint)
	if len(entries) == 0 {
		return false, fmt.Errorf("auth: unknown key hint %x", hint)
	}
	if len(tag) != s.tagLen {
		return false, fmt.Errorf("auth: tag length mismatch: got %d, want %d", len(tag), s.tagLen)
	}
	for _, entry := range entries {
		ok, err := entry.Deriver.VerifyAuthTag(serverRandom, recordBytes, tag)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// AddUser 在运行时添加或替换用户。线程安全。
// 如果 pskHex 为空，PSK 派生为 SHA256(userID)。
// 如果同一 userID 已存在，则替换；相同 hint 的其他用户会保留在候选桶中。
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
	if len(psk) != keyderiv.DefaultKeyLen {
		return fmt.Errorf("auth: invalid PSK length for user %q: got %d bytes, want %d", userID, len(psk), keyderiv.DefaultKeyLen)
	}

	hint := keyderiv.ComputeKeyHint(userID)
	entry := &UserEntry{
		UserID:  userID,
		Deriver: keyderiv.NewDeriver(psk),
	}
	entries := s.byHint[hint]
	for i, existing := range entries {
		if existing.UserID == userID {
			entries[i] = entry
			s.byHint[hint] = entries
			return nil
		}
	}
	s.byHint[hint] = append(entries, entry)
	return nil
}

// RemoveUserByID 通过用户标识符删除用户。线程安全。
// 如果未找到用户则返回错误。
func (s *UserStore) RemoveUserByID(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hint := keyderiv.ComputeKeyHint(userID)
	entries := s.byHint[hint]
	for i, entry := range entries {
		if entry.UserID != userID {
			continue
		}
		entries = append(entries[:i], entries[i+1:]...)
		if len(entries) == 0 {
			delete(s.byHint, hint)
		} else {
			s.byHint[hint] = entries
		}
		return nil
	}
	if len(entries) == 0 {
		return fmt.Errorf("auth: user %q not found (hint %x)", userID, hint)
	}
	return fmt.Errorf("auth: user %q not found in hint bucket %x", userID, hint)
}

// ListUserIDs 返回所有当前注册的用户标识符。线程安全。
func (s *UserStore) ListUserIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, s.countLocked())
	for _, entries := range s.byHint {
		for _, entry := range entries {
			ids = append(ids, entry.UserID)
		}
	}
	return ids
}

// GetAllDerivers 返回所有用户的派生器，用于多用户记录扫描。
// 线程安全。
func (s *UserStore) GetAllDerivers() []*keyderiv.Deriver {
	s.mu.RLock()
	defer s.mu.RUnlock()
	derivers := make([]*keyderiv.Deriver, 0, s.countLocked())
	for _, entries := range s.byHint {
		for _, entry := range entries {
			derivers = append(derivers, entry.Deriver)
		}
	}
	return derivers
}

// GetDeriversByHint returns only the candidate derivers for a key hint.
// The returned slice is detached from the store bucket so callers can iterate
// without holding the store lock.
func (s *UserStore) GetDeriversByHint(hint [4]byte) []*keyderiv.Deriver {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := s.lookup(hint)
	derivers := make([]*keyderiv.Deriver, 0, len(entries))
	for _, entry := range entries {
		derivers = append(derivers, entry.Deriver)
	}
	return derivers
}

// Count 返回注册用户数。线程安全。
func (s *UserStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.countLocked()
}

// countLocked 返回注册用户数。调用者必须持有 s.mu。
func (s *UserStore) countLocked() int {
	count := 0
	for _, entries := range s.byHint {
		count += len(entries)
	}
	return count
}

// ExtractKeyHint 从认证帧负载中提取 4 字节密钥提示。
// 提示是负载的前 4 个字节。
func ExtractKeyHint(payload []byte) ([4]byte, error) {
	var hint [4]byte
	if len(payload) < 4 {
		return hint, errors.New("auth: payload too short for key hint (need 4 bytes)")
	}
	copy(hint[:], payload[:4])
	return hint, nil
}

// ExtractTagFromHintFrame 从包含 4 字节密钥提示前缀的负载中提取认证标签。
// 返回提示之后的标签字节。
func ExtractTagFromHintFrame(payload []byte, tagLen int) ([]byte, error) {
	if len(payload) < 4+tagLen {
		return nil, fmt.Errorf("auth: payload too short for hint frame (got %d, need %d)", len(payload), 4+tagLen)
	}
	tag := make([]byte, tagLen)
	copy(tag, payload[4:4+tagLen])
	return tag, nil
}
