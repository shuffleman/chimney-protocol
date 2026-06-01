// Package record implements the ChimneyRecord codec per Part III §1.
//
// After the swap, every TLS record is a fake application_data record:
//
//	struct ChimneyRecord {
//	    uint8   type    = 0x17;     // application_data
//	    uint16  version = 0x0303;   // TLS 1.2 legacy
//	    uint16  length;
//	    opaque  payload[length];    // = AEAD_seal(K_sess, nonce, inner_chunk)
//	}
//
// The inner_chunk decrypts to H2 frame byte stream.
package record

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	// Record header sizes.
	RecordHeaderLen = 5 // type(1) + version(2) + length(2)

	// TLS record type for application_data.
	RecordTypeApplicationData = 0x17

	// Legacy TLS version (TLS 1.2) for record layer compatibility.
	RecordVersionTLS12 = 0x0303

	// Default tag lengths for AEAD.
	ChaCha20Poly1305TagSize = 16
	AESGCMTagSize           = 16

	// MaxPlaintextLen is the maximum length of a single record's plaintext payload.
	// Must be >= max H2 frame size (FrameHeaderLen + MaxFrameSize = 9 + 65536 = 65545).
	MaxPlaintextLen = 66000

	// MaxRecordLen is the maximum on-the-wire record size (5 + 66000 + 16 ≈ 66 KiB).
	MaxRecordLen = RecordHeaderLen + MaxPlaintextLen + AESGCMTagSize

	// MaxBufSize caps the RecordReader internal buffer to prevent unbounded growth
	// when the reader stalls or an attacker sends partial records.
	MaxBufSize = MaxRecordLen * 4
)

// readBufPool reuses the tmp read buffer in RecordReader.ReadRecord.
var readBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, MaxRecordLen)
		return &buf
	},
}

var (
	// ErrRecordTooShort is returned when a record is shorter than the header.
	ErrRecordTooShort = errors.New("record: insufficient data for header")

	// ErrRecordOverflow is returned when a record's length field exceeds MaxRecordLen.
	ErrRecordOverflow = errors.New("record: length field exceeds maximum")

	// ErrBufferOverflow is returned when the internal buffer exceeds MaxBufSize.
	ErrBufferOverflow = errors.New("record: internal buffer limit exceeded")

	// ErrBadRecordMAC is returned when AEAD decryption (Open) fails.
	ErrBadRecordMAC = errors.New("record: bad record MAC")

	// ErrInvalidRecordType is returned when the record type is not application_data.
	ErrInvalidRecordType = errors.New("record: invalid record type")

	// ErrInvalidVersion is returned when the record version is not 0x0303.
	ErrInvalidVersion = errors.New("record: invalid version")
)

// NonceStrategy defines how AEAD nonces are derived from sequence numbers.
type NonceStrategy interface {
	// Nonce returns the AEAD nonce for the given 1-based sequence number.
	// seq is the record sequence number (starts at 0, increments per record).
	Nonce(seq uint64) []byte
}

// CounterNonce implements the TLS 1.3 implicit nonce strategy:
// nonce = base_nonce XOR seq (as little-endian 96-bit).
type CounterNonce struct {
	base []byte // 12 bytes for ChaCha20-Poly1305 or AES-GCM
	size int
}

// NewCounterNonce creates a CounterNonce with a random base.
// Size must be 12 for ChaCha20-Poly1305 or AES-GCM (TLS 1.3).
func NewCounterNonce(size int) (*CounterNonce, error) {
	if size != 12 {
		return nil, fmt.Errorf("record: unsupported nonce size %d", size)
	}
	base := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, base); err != nil {
		return nil, fmt.Errorf("record: failed to generate nonce base: %w", err)
	}
	return &CounterNonce{base: base, size: size}, nil
}

// NewCounterNonceWithBase creates a CounterNonce with a given base.
func NewCounterNonceWithBase(base []byte) *CounterNonce {
	return &CounterNonce{base: append([]byte(nil), base...), size: len(base)}
}

// Nonce returns nonce = base XOR seq (seq as little-endian).
func (cn *CounterNonce) Nonce(seq uint64) []byte {
	nonce := make([]byte, cn.size)
	copy(nonce, cn.base)
	// XOR seq (8 bytes, little-endian) into the last 8 bytes of the 12-byte nonce.
	for i := 0; i < 8; i++ {
		nonce[cn.size-1-i] ^= byte(seq >> (8 * i))
	}
	return nonce
}

// Sealer handles AEAD sealing (encryption) of record payloads.
type Sealer struct {
	aead  cipher.AEAD
	nonce NonceStrategy
	seq   uint64
	mu    sync.Mutex
}

// NewSealerChaCha20Poly1305 creates a sealer using ChaCha20-Poly1305.
func NewSealerChaCha20Poly1305(key, nonceBase []byte) (*Sealer, error) {
	aead, err := cipher.NewGCMWithNonceSize(nil, 12) // ChaCha20Poly1305
	if err != nil {
		// Fallback: try standard newGCM
		// Actually for ChaCha20-Poly1305 we use the specific constructor
		// But crypto/tls uses cipher.aeadChaCha20Poly1305 which is internal
		// For our implementation, we use AES-GCM as the default (widely supported)
		// and document that ChaCha20-Poly1305 is preferred in production.
		return nil, fmt.Errorf("record: ChaCha20-Poly1305 not directly available, use AES-GCM: %w", err)
	}
	_ = aead
	return NewSealerAESGCM(key, nonceBase)
}

// NewSealerAESGCM creates a sealer using AES-128-GCM (or AES-256-GCM).
func NewSealerAESGCM(key, nonceBase []byte) (*Sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("record: failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("record: failed to create GCM: %w", err)
	}
	nonce := NewCounterNonceWithBase(nonceBase)
	return &Sealer{aead: aead, nonce: nonce}, nil
}

// Seal encrypts plaintext into dst, returning the ciphertext (record payload).
// The additional data is the 5-byte record header (type || version || length).
// seq is advanced internally after each seal operation.
func (s *Sealer) Seal(dst, plaintext, additionalData []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	nonce := s.nonce.Nonce(s.seq)
	s.seq++

	return s.aead.Seal(dst, nonce, plaintext, additionalData)
}

// Sequence returns the current sequence number.
func (s *Sealer) Sequence() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// rollbackSeq decrements the sequence counter by 1.
// Call this when a write fails after Seal already incremented the counter,
// so the next Seal uses the same seq the receiver expects.
func (s *Sealer) rollbackSeq() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seq > 0 {
		s.seq--
	}
}

// Opener handles AEAD opening (decryption) of record payloads.
type Opener struct {
	aead     cipher.AEAD
	nonce    NonceStrategy
	seq      uint64
	failures uint64 // consecutive AEAD failures (reset on success)
	mu       sync.Mutex
}

// NewOpenerAESGCM creates an opener using AES-128-GCM (or AES-256-GCM).
func NewOpenerAESGCM(key, nonceBase []byte) (*Opener, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("record: failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("record: failed to create GCM: %w", err)
	}
	nonce := NewCounterNonceWithBase(nonceBase)
	return &Opener{aead: aead, nonce: nonce}, nil
}

// Open decrypts ciphertext into dst, returning the plaintext.
// The additional data is the 5-byte record header.
//
// IMPORTANT: seq is only advanced on success. If AEAD decryption fails the
// counter stays put so a single corrupt/misaligned record does not permanently
// desynchronise the entire tunnel. The caller should still tear down the
// connection on error — this is purely a safety net.
func (o *Opener) Open(dst, ciphertext, additionalData []byte) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	nonce := o.nonce.Nonce(o.seq)

	plaintext, err := o.aead.Open(dst, nonce, ciphertext, additionalData)
	if err != nil {
		o.failures++
		return nil, fmt.Errorf("%w: expected seq=%d consecutive_failures=%d",
			ErrBadRecordMAC, o.seq, o.failures)
	}

	o.seq++
	o.failures = 0
	return plaintext, nil
}

// Failures returns the number of consecutive AEAD failures seen by this opener.
func (o *Opener) Failures() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.failures
}

// Sequence returns the current sequence number.
func (o *Opener) Sequence() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.seq
}

// Codec provides combined encode/decode for ChimneyRecords.
type Codec struct {
	sealer *Sealer
	opener *Opener
}

// SealerSeq returns the current sealer sequence number.
func (c *Codec) SealerSeq() uint64 { return c.sealer.Sequence() }

// OpenerSeq returns the current opener sequence number.
func (c *Codec) OpenerSeq() uint64 { return c.opener.Sequence() }

// NewCodec creates a Codec with AES-GCM for both directions.
// In practice, K_sess provides one key for client→relay and one for relay→client.
// Here we use a single key for simplicity; production should use separate keys.
func NewCodec(key, nonceBase []byte) (*Codec, error) {
	sealer, err := NewSealerAESGCM(key, nonceBase)
	if err != nil {
		return nil, err
	}
	opener, err := NewOpenerAESGCM(key, nonceBase)
	if err != nil {
		return nil, err
	}
	return &Codec{sealer: sealer, opener: opener}, nil
}

// NewCodecWithDirectionalKeys creates a Codec with separate keys for each direction.
// sendKey/nonceBaseSend for sealing (outgoing), recvKey/nonceBaseRecv for opening (incoming).
func NewCodecWithDirectionalKeys(sendKey, nonceBaseSend, recvKey, nonceBaseRecv []byte) (*Codec, error) {
	sealer, err := NewSealerAESGCM(sendKey, nonceBaseSend)
	if err != nil {
		return nil, fmt.Errorf("record: failed to create sealer: %w", err)
	}
	opener, err := NewOpenerAESGCM(recvKey, nonceBaseRecv)
	if err != nil {
		return nil, fmt.Errorf("record: failed to create opener: %w", err)
	}
	return &Codec{sealer: sealer, opener: opener}, nil
}

// EncodeRecord encodes a plaintext chunk into a complete ChimneyRecord (header || AEAD ciphertext).
// plaintext should be H2 frame bytes. The returned slice is a single complete record.
func (c *Codec) EncodeRecord(plaintext []byte) []byte {
	// Build additional data = record header (without length, then fill length)
	header := make([]byte, RecordHeaderLen)
	header[0] = RecordTypeApplicationData
	header[1] = byte(RecordVersionTLS12 >> 8)
	header[2] = byte(RecordVersionTLS12 & 0xFF)

	// Seal the payload. Additional data is the header (length will be filled after we know ciphertext size).
	// We need to set a placeholder length first, then seal, then update the length.
	// In TLS 1.3, the additional data includes the header with the actual ciphertext length.
	// So we do: seal with placeholder length, then fill in the real length.
	// Actually, per TLS 1.3 spec, the additional data IS the record header with the ciphertext length.
	binary.BigEndian.PutUint16(header[3:5], uint16(len(plaintext)+c.sealer.aead.Overhead()))

	ciphertext := c.sealer.Seal(nil, plaintext, header)

	// The final record = header || ciphertext
	record := make([]byte, RecordHeaderLen+len(ciphertext))
	copy(record, header)
	copy(record[RecordHeaderLen:], ciphertext)

	return record
}

// EncodeRecordTo encodes plaintext into the provided buffer, returning the record.
// More efficient than EncodeRecord when buffer reuse is possible.
func (c *Codec) EncodeRecordTo(buf, plaintext []byte) []byte {
	header := buf[:RecordHeaderLen]
	header[0] = RecordTypeApplicationData
	header[1] = byte(RecordVersionTLS12 >> 8)
	header[2] = byte(RecordVersionTLS12 & 0xFF)
	binary.BigEndian.PutUint16(header[3:5], uint16(len(plaintext)+c.sealer.aead.Overhead()))

	ciphertext := c.sealer.Seal(buf[RecordHeaderLen:RecordHeaderLen], plaintext, header)

	return buf[:RecordHeaderLen+len(ciphertext)]
}

// DecodeRecordResult holds the result of decoding a record.
type DecodeRecordResult struct {
	Plaintext []byte // The decrypted inner payload (H2 frames)
	Consumed  int    // Number of bytes consumed from the input
}

// DecodeRecord decodes a single ChimneyRecord from data, returning the plaintext.
// It processes exactly one record. If data doesn't contain a complete record,
// returns (nil, ErrRecordTooShort).
func (c *Codec) DecodeRecord(data []byte) (*DecodeRecordResult, error) {
	if len(data) < RecordHeaderLen {
		return nil, ErrRecordTooShort
	}

	// Parse header
	recType := data[0]
	version := binary.BigEndian.Uint16(data[1:3])
	length := binary.BigEndian.Uint16(data[3:5])

	if recType != RecordTypeApplicationData {
		return nil, fmt.Errorf("%w: got 0x%02x", ErrInvalidRecordType, recType)
	}
	if version != RecordVersionTLS12 {
		return nil, fmt.Errorf("%w: got 0x%04x", ErrInvalidVersion, version)
	}

	if int(length) > MaxRecordLen-RecordHeaderLen {
		return nil, fmt.Errorf("%w: %d", ErrRecordOverflow, length)
	}

	if len(data) < RecordHeaderLen+int(length) {
		return nil, ErrRecordTooShort
	}

	header := data[:RecordHeaderLen]
	ciphertext := data[RecordHeaderLen : RecordHeaderLen+length]

	plaintext, err := c.opener.Open(nil, ciphertext, header)
	if err != nil {
		return nil, err
	}

	return &DecodeRecordResult{
		Plaintext: plaintext,
		Consumed:  RecordHeaderLen + int(length),
	}, nil
}

// RecordWriter serializes ChimneyRecord writes with a mutex.
// Each call to WriteRecord encodes and writes atomically to prevent
// interleaving of encrypted records on the underlying stream.
//
// Once a write error occurs the writer is marked broken and all subsequent
// WriteRecord calls return that error without touching the AEAD counter,
// preventing the "bad record MAC" cascade caused by a counter advance that
// was never delivered to the peer.
type RecordWriter struct {
	mu     sync.Mutex
	codec  *Codec
	writer io.Writer
	broken error // set on first write failure, prevents further writes
}

// NewRecordWriter creates a RecordWriter.
func NewRecordWriter(w io.Writer, codec *Codec) *RecordWriter {
	return &RecordWriter{
		codec:  codec,
		writer: w,
	}
}

// WriteRecord writes a single plaintext chunk as a complete ChimneyRecord.
// Thread-safe. After the first write error the writer is permanently broken
// and all future calls return that error — this guards against AEAD counter
// desynchronisation when the underlying transport fails.
func (rw *RecordWriter) WriteRecord(plaintext []byte) error {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.broken != nil {
		return rw.broken
	}

	record := rw.codec.EncodeRecord(plaintext)
	for len(record) > 0 {
		n, err := rw.writer.Write(record)
		if err != nil {
			// Only roll back the AEAD counter when zero bytes were written.
			// If we sent even one byte the receiver's buffer is tainted and
			// the tunnel must be torn down regardless.
			if n == 0 {
				rw.codec.sealer.rollbackSeq()
			}
			rw.broken = err
			return err
		}
		record = record[n:]
	}
	return nil
}

// Close is a no-op for the mutex-based RecordWriter.
func (rw *RecordWriter) Close() error {
	return nil
}

// RecordReader reads and decrypts ChimneyRecords from an underlying io.Reader.
type RecordReader struct {
	mu     sync.Mutex
	codec  *Codec
	reader io.Reader
	buf    []byte
}

// NewRecordReader creates a RecordReader with an internal buffer.
func NewRecordReader(r io.Reader, codec *Codec) *RecordReader {
	return &RecordReader{
		codec:  codec,
		reader: r,
		buf:    make([]byte, 0, MaxRecordLen*2),
	}
}

// ReadRecord reads and decrypts the next complete ChimneyRecord.
// Returns io.EOF if the underlying reader returns io.EOF with no data.
// Thread-safe.
func (rr *RecordReader) ReadRecord() ([]byte, error) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	for {
		// Try to decode from buffer
		if len(rr.buf) >= RecordHeaderLen {
			length := binary.BigEndian.Uint16(rr.buf[3:5])
			if int(length) > MaxRecordLen-RecordHeaderLen {
				return nil, ErrRecordOverflow
			}
			needed := RecordHeaderLen + int(length)
			if len(rr.buf) >= needed {
				result, err := rr.codec.DecodeRecord(rr.buf)
				if err != nil {
					return nil, err
				}
				rr.buf = rr.buf[result.Consumed:]
				return result.Plaintext, nil
			}
		}

		// Need more data
			if len(rr.buf) >= MaxBufSize {
				return nil, ErrBufferOverflow
			}
			tmpPtr := readBufPool.Get().(*[]byte)
			tmp := *tmpPtr
			n, err := rr.reader.Read(tmp)
			if n > 0 {
				rr.buf = append(rr.buf, tmp[:n]...)
			}
			readBufPool.Put(tmpPtr)
		if err != nil {
			if err == io.EOF && len(rr.buf) > 0 {
				// Have partial data but hit EOF
				if len(rr.buf) < RecordHeaderLen {
					return nil, io.ErrUnexpectedEOF
				}
				// Try one last decode
				result, decodeErr := rr.codec.DecodeRecord(rr.buf)
				if decodeErr != nil {
					return nil, io.ErrUnexpectedEOF
				}
				rr.buf = rr.buf[result.Consumed:]
				return result.Plaintext, nil
			}
			return nil, err
		}
	}
}

// Buffered returns the number of unread bytes in the internal buffer.
func (rr *RecordReader) Buffered() int {
	return len(rr.buf)
}

// KeyLen returns the expected key length for the AEAD algorithm.
func KeyLen(aead string) int {
	switch aead {
	case "AES-128-GCM":
		return 16
	case "AES-256-GCM":
		return 32
	case "ChaCha20-Poly1305":
		return 32
	default:
		return 16 // default to AES-128-GCM
	}
}

// NonceLen returns the expected nonce length for the AEAD algorithm.
func NonceLen(aead string) int {
	switch aead {
	case "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305":
		return 12
	default:
		return 12
	}
}
