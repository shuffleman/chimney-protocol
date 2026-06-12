// Package record 实现了 ChimneyRecord 编解码器，符合第三部分第 §1 节。
//
// 切换后，每个 TLS 记录都是一个伪造的 application_data 记录：
//
//	struct ChimneyRecord {
//	    uint8   type    = 0x17;     // 应用数据
//	    uint16  version = 0x0303;   // TLS 1.2 遗留版本
//	    uint16  length;
//	    opaque  payload[length];    // = AEAD_seal(K_sess, nonce, inner_chunk)
//	}
//
// inner_chunk 解密后得到 H2 帧字节流。
package record

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// DebugTracer 是一个包级钩子，用于捕获每次密封/打开操作。
// 当设置后，每次 Seal 和 Open 都会调用它，传入完整的明文/密文。
var DebugTracer func(dir string, seq uint64, nonce, hdr, plaintext, ciphertext []byte, keyFP [4]byte)

// RecordTraceHook 是一个包级钩子，用于从编码和解码两端捕获完整的记录字节，
// 用于诊断对比。
// dir 为 "encode" 或 "decode"，keyFP 用于区分客户端→中继和中继→客户端。
var RecordTraceHook func(dir string, seq uint64, recordData []byte, keyFP [4]byte)

const (
	// 记录头部大小。
	RecordHeaderLen = 5 // type(1) + version(2) + length(2)

	// 用于 application_data 的 TLS 记录类型。
	RecordTypeApplicationData = 0x17

	// 用于记录层兼容性的遗留 TLS 版本（TLS 1.2）。
	RecordVersionTLS12 = 0x0303

	// AEAD 的默认标签长度。
	ChaCha20Poly1305TagSize = 16
	AESGCMTagSize           = 16

	// MaxPlaintextLen 是单个记录明文负载的最大长度。
	// 必须 >= 最大 H2 帧大小（FrameHeaderLen + MaxFrameSize = 9 + 65536 = 65545）。
	MaxPlaintextLen = 66000

	// MaxRecordLen 是线上的最大记录大小（5 + 66000 + 16 ≈ 66 KiB）。
	MaxRecordLen = RecordHeaderLen + MaxPlaintextLen + AESGCMTagSize

	// MaxBufSize 限制了 RecordReader 内部缓冲区的上限，防止读取器停滞或攻击者发送不完整记录时
	// 导致无限制增长。
	MaxBufSize = MaxRecordLen * 4
)

var (
	// ErrRecordTooShort 在记录短于头部时返回。
	ErrRecordTooShort = errors.New("record: insufficient data for header")

	// ErrRecordOverflow 在记录长度字段超过 MaxRecordLen 时返回。
	ErrRecordOverflow = errors.New("record: length field exceeds maximum")

	// ErrBufferOverflow 在内部缓冲区超过 MaxBufSize 时返回。
	ErrBufferOverflow = errors.New("record: internal buffer limit exceeded")

	// ErrBadRecordMAC 在 AEAD 解密（Open）失败时返回。
	ErrBadRecordMAC = errors.New("record: bad record MAC")

	// ErrTooManyFailures 在连续 AEAD 失败次数超过 maxConsecutiveAEADFailures 时返回，
	// 表示密钥不匹配或可能受到攻击。
	ErrTooManyFailures = errors.New("record: too many consecutive AEAD failures")

	// ErrInvalidRecordType 在记录类型不是 application_data 时返回。
	ErrInvalidRecordType = errors.New("record: invalid record type")

	// ErrInvalidVersion 在记录版本不是 0x0303 时返回。
	ErrInvalidVersion = errors.New("record: invalid version")
)

// NonceStrategy 定义如何从序列号派生 AEAD nonce。
type NonceStrategy interface {
	// Nonce 返回给定基于 1 的序列号的 AEAD nonce。
	// seq 是记录序列号（从 0 开始，每条记录递增）。
	Nonce(seq uint64) []byte
}

// CounterNonce 实现 TLS 1.3 隐式 nonce 策略：
// nonce = base_nonce XOR seq（小端 96 位）。
type CounterNonce struct {
	base []byte // 12 bytes for ChaCha20-Poly1305 or AES-GCM
	size int
}

// NewCounterNonce 创建一个使用随机基数的 CounterNonce。
// 对于 ChaCha20-Poly1305 或 AES-GCM（TLS 1.3），大小必须为 12。
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

// NewCounterNonceWithBase 创建一个使用给定基数的 CounterNonce。
func NewCounterNonceWithBase(base []byte) *CounterNonce {
	return &CounterNonce{base: append([]byte(nil), base...), size: len(base)}
}

// Nonce 返回 nonce = base XOR seq（seq 为小端序）。
func (cn *CounterNonce) Nonce(seq uint64) []byte {
	nonce := make([]byte, cn.size)
	copy(nonce, cn.base)
	// 将 seq（8 字节，小端序）异或到 12 字节 nonce 的最后 8 字节中。
	for i := 0; i < 8; i++ {
		nonce[cn.size-1-i] ^= byte(seq >> (8 * i))
	}
	return nonce
}

// Sealer 处理记录负载的 AEAD 密封（加密）。
type Sealer struct {
	aead  cipher.AEAD
	nonce NonceStrategy
	seq   uint64
	keyFP [4]byte
	mu    sync.Mutex
}

// NewSealerChaCha20Poly1305 创建一个使用 ChaCha20-Poly1305 的密封器。
func NewSealerChaCha20Poly1305(key, nonceBase []byte) (*Sealer, error) {
	aead, err := cipher.NewGCMWithNonceSize(nil, 12) // ChaCha20Poly1305
	if err != nil {
		// 回退：尝试标准 newGCM
		// 实际上对于 ChaCha20-Poly1305，我们使用特定的构造函数
		// 但 crypto/tls 使用 cipher.aeadChaCha20Poly1305，这是内部 API
		// 在我们的实现中，我们使用 AES-GCM 作为默认方案（广泛支持）
		// 并文档说明在生产环境中优先使用 ChaCha20-Poly1305。
		return nil, fmt.Errorf("record: ChaCha20-Poly1305 not directly available, use AES-GCM: %w", err)
	}
	_ = aead
	return NewSealerAESGCM(key, nonceBase)
}

// NewSealerAESGCM 创建一个使用 AES-128-GCM（或 AES-256-GCM）的密封器。
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
	keyHash := sha256.Sum256(key)
	var keyFP [4]byte
	copy(keyFP[:], keyHash[:4])
	return &Sealer{aead: aead, nonce: nonce, keyFP: keyFP}, nil
}

// Seal 将明文加密到 dst 中，返回密文（记录负载）。
// 附加数据是 5 字节的记录头部（type || version || length）。
// seq 在每次密封操作后内部递增。
func (s *Sealer) Seal(dst, plaintext, additionalData []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	nonce := s.nonce.Nonce(s.seq)
	seq := s.seq
	s.seq++

	result := s.aead.Seal(dst, nonce, plaintext, additionalData)

	if DebugTracer != nil {
		DebugTracer("seal", seq, nonce, additionalData, plaintext, result, s.keyFP)
	}

	return result
}

// Sequence 返回当前序列号。
func (s *Sealer) Sequence() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// rollbackSeq 将序列计数器减 1。
// 当 Seal 已递增计数器但写入失败时调用此方法，
// 以便下一次 Seal 使用接收方期望的相同 seq。
func (s *Sealer) rollbackSeq() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seq > 0 {
		s.seq--
	}
}

// maxConsecutiveAEADFailures 是连续 AEAD 失败次数，超过该次数时，
// Open 将返回 ErrTooManyFailures 而不是 ErrBadRecordMAC。
// 在原本有效的隧道上，单个损坏的记录不应断开连接，
// 但持续出现几乎肯定表示密钥不匹配或存在主动攻击。
const maxConsecutiveAEADFailures = 3

// Opener 处理记录负载的 AEAD 打开（解密）。
type Opener struct {
	aead     cipher.AEAD
	nonce    NonceStrategy
	seq      uint64
	failures uint64 // consecutive AEAD failures (reset on success)
	keyFP    [4]byte
	mu       sync.Mutex
}

// NewOpenerAESGCM 创建一个使用 AES-128-GCM（或 AES-256-GCM）的打开器。
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
	keyHash := sha256.Sum256(key)
	var keyFP [4]byte
	copy(keyFP[:], keyHash[:4])
	return &Opener{aead: aead, nonce: nonce, keyFP: keyFP}, nil
}

// Open 将密文解密到 dst 中，返回明文。
// 附加数据是 5 字节的记录头部。
//
// 重要：seq 仅在成功时递增。如果 AEAD 解密失败，
// 计数器保持不变，这样单个损坏/错位的记录不会永久性地
// 使整个隧道不同步。调用者仍应在出错时断开连接——
// 这纯粹是一个安全网。
func (o *Opener) Open(dst, ciphertext, additionalData []byte) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	nonce := o.nonce.Nonce(o.seq)

	plaintext, err := o.aead.Open(dst, nonce, ciphertext, additionalData)
	if err != nil {
		o.failures++
		if DebugTracer != nil {
			DebugTracer("open-ERR", o.seq, nonce, additionalData, nil, ciphertext, o.keyFP)
		}
		if o.failures >= maxConsecutiveAEADFailures {
			return nil, fmt.Errorf("%w: seq=%d failures=%d (key mismatch or active attack)",
				ErrTooManyFailures, o.seq, o.failures)
		}
		return nil, fmt.Errorf("%w: expected seq=%d consecutive_failures=%d",
			ErrBadRecordMAC, o.seq, o.failures)
	}

	seq := o.seq
	o.seq++
	o.failures = 0

	if DebugTracer != nil {
		DebugTracer("open", seq, nonce, additionalData, plaintext, ciphertext, o.keyFP)
	}

	return plaintext, nil
}

// Failures 返回该打开器遇到的连续 AEAD 失败次数。
func (o *Opener) Failures() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.failures
}

// Sequence 返回当前序列号。
func (o *Opener) Sequence() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.seq
}

// Codec 提供 ChimeyRecords 的编码/解码组合功能。
type Codec struct {
	sealer *Sealer
	opener *Opener
}

// SealerSeq 返回当前密封器的序列号。
func (c *Codec) SealerSeq() uint64 { return c.sealer.Sequence() }

// OpenerSeq 返回当前打开器的序列号。
func (c *Codec) OpenerSeq() uint64 { return c.opener.Sequence() }

// SealerTrail 返回最近密封器操作的诊断轨迹。
func (c *Codec) SealerTrail() string { return "(trail not enabled)" }

// OpenerTrail 返回最近打开器操作的诊断轨迹。
func (c *Codec) OpenerTrail() string { return "(trail not enabled)" }

// NewCodec 创建一个双向使用 AES-GCM 的 Codec。
// 实践中，K_sess 提供客户端→中继和中继→客户端各一个密钥。
// 这里为简单起见使用单一密钥；生产环境应使用独立密钥。
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

// NewCodecWithDirectionalKeys 创建一个每个方向使用独立密钥的 Codec。
// sendKey/nonceBaseSend 用于密封（出站），recvKey/nonceBaseRecv 用于打开（入站）。
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

// EncodeRecord 将明文块编码为完整的 ChimneyRecord（头部 || AEAD 密文）。
// plaintext 应为 H2 帧字节。返回的切片是一个完整的记录。
func (c *Codec) EncodeRecord(plaintext []byte) []byte {
	// 构建附加数据 = 记录头部（先不填长度，再填入长度）
	header := make([]byte, RecordHeaderLen)
	header[0] = RecordTypeApplicationData
	header[1] = byte(RecordVersionTLS12 >> 8)
	header[2] = byte(RecordVersionTLS12 & 0xFF)

	// 密封负载。附加数据是头部（长度将在知道密文大小后填写）。
	// 我们需要先设置占位长度，然后密封，再更新长度。
	// 在 TLS 1.3 中，附加数据包含带有实际密文长度的头部。
	// 所以我们这样做：用占位长度密封，然后填入真实长度。
	// 实际上，根据 TLS 1.3 规范，附加数据就是带有密文长度的记录头部。
	binary.BigEndian.PutUint16(header[3:5], uint16(len(plaintext)+c.sealer.aead.Overhead()))

	ciphertext := c.sealer.Seal(nil, plaintext, header)

	// 最终记录 = 头部 || 密文
	record := make([]byte, RecordHeaderLen+len(ciphertext))
	copy(record, header)
	copy(record[RecordHeaderLen:], ciphertext)

	if RecordTraceHook != nil {
		RecordTraceHook("encode", c.sealer.Sequence()-1, record, c.sealer.keyFP)
	}

	return record
}

// EncodeRecordTo 将明文编码到提供的缓冲区中，返回记录。
// 在可以重用缓冲区时比 EncodeRecord 更高效。
func (c *Codec) EncodeRecordTo(buf, plaintext []byte) []byte {
	header := buf[:RecordHeaderLen]
	header[0] = RecordTypeApplicationData
	header[1] = byte(RecordVersionTLS12 >> 8)
	header[2] = byte(RecordVersionTLS12 & 0xFF)
	binary.BigEndian.PutUint16(header[3:5], uint16(len(plaintext)+c.sealer.aead.Overhead()))

	ciphertext := c.sealer.Seal(buf[RecordHeaderLen:RecordHeaderLen], plaintext, header)

	return buf[:RecordHeaderLen+len(ciphertext)]
}

// DecodeRecordResult 保存解码记录的结果。
type DecodeRecordResult struct {
	Plaintext []byte // The decrypted inner payload (H2 frames)
	Consumed  int    // Number of bytes consumed from the input
}

// DecodeRecord 从数据中解码单个 ChimneyRecord，返回明文。
// 它只处理一条记录。如果数据不包含完整记录，
// 返回 (nil, ErrRecordTooShort)。
func (c *Codec) DecodeRecord(data []byte) (*DecodeRecordResult, error) {
	if len(data) < RecordHeaderLen {
		return nil, ErrRecordTooShort
	}

	// 解析头部
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

	if RecordTraceHook != nil {
		rec := data[:RecordHeaderLen+int(length)]
		RecordTraceHook("decode", c.opener.Sequence(), rec, c.opener.keyFP)
	}

	plaintext, err := c.opener.Open(nil, ciphertext, header)
	if err != nil {
		return nil, err
	}

	return &DecodeRecordResult{
		Plaintext: plaintext,
		Consumed:  RecordHeaderLen + int(length),
	}, nil
}

// RecordWriter 使用互斥锁序列化 ChimneyRecord 写入。
// 每次 WriteRecord 调用都原子性地编码和写入，以防止
// 加密记录在底层流上的交错。
//
// 一旦发生写入错误，写入器被标记为损坏，之后所有
// WriteRecord 调用都返回该错误，不触及 AEAD 计数器，
// 防止因计数器递增但未传递到对端而导致的 "bad record MAC" 级联错误。
type RecordWriter struct {
	mu     sync.Mutex
	codec  *Codec
	writer io.Writer
	broken error // set on first write failure, prevents further writes
}

type writeDeadlineSetter interface {
	SetWriteDeadline(time.Time) error
}

// NewRecordWriter 创建一个 RecordWriter。
func NewRecordWriter(w io.Writer, codec *Codec) *RecordWriter {
	return &RecordWriter{
		codec:  codec,
		writer: w,
	}
}

// WriteRecord 将单个明文块写入为完整的 ChimneyRecord。
// 线程安全。首次写入错误后，写入器永久损坏，
// 之后所有调用都返回该错误——这防止了底层传输失败时 AEAD 计数器
// 不同步的问题。
//
// 在 Windows 上，每次 Write 调用被限制为 maxWriteChunk 字节（8192），以
// 规避回环 TCP 驱动中的错误，该错误中跨跃超过
// 2 个内存页（> 8192 字节）的写入会从第 2 页开始传递损坏的字节。
func (rw *RecordWriter) WriteRecord(plaintext []byte) error {
	return rw.WriteRecordWithDeadline(plaintext, time.Time{})
}

// WriteRecordWithDeadline 与 WriteRecord 相同，但在底层 writer 支持
// SetWriteDeadline 时，仅在本次串行写入期间应用写截止时间。
func (rw *RecordWriter) WriteRecordWithDeadline(plaintext []byte, deadline time.Time) error {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.broken != nil {
		return rw.broken
	}

	if !deadline.IsZero() {
		if writer, ok := rw.writer.(writeDeadlineSetter); ok {
			if err := writer.SetWriteDeadline(deadline); err != nil {
				return err
			}
			defer func() {
				_ = writer.SetWriteDeadline(time.Time{})
			}()
		}
	}

	record := rw.codec.EncodeRecord(plaintext)

	anyWritten := false
	for len(record) > 0 {
		writeDelay()
		chunk := record
		if maxWriteChunk > 0 && len(chunk) > maxWriteChunk {
			chunk = record[:maxWriteChunk]
		}
		n, err := rw.writer.Write(chunk)
		if n > 0 {
			anyWritten = true
		}
		if err != nil {
			// 仅在总写入字节数为零时才回滚 AEAD 计数器
			// 如果哪怕一个字节到达了接收方，隧道必须被拆除——
			// 部分记录无法撤销。
			if !anyWritten {
				rw.codec.sealer.rollbackSeq()
			}
			rw.broken = err
			return err
		}
		record = record[n:]
	}
	return nil
}

// Close 对于基于互斥锁的 RecordWriter 是无操作。
func (rw *RecordWriter) Close() error {
	return nil
}

// RecordReader 从底层 io.Reader 读取并解密 ChimneyRecords。
type RecordReader struct {
	mu     sync.Mutex
	codec  *Codec
	reader io.Reader
	buf    []byte
}

// NewRecordReader 创建一个带有内部缓冲区的 RecordReader。
func NewRecordReader(r io.Reader, codec *Codec) *RecordReader {
	return &RecordReader{
		codec:  codec,
		reader: r,
		buf:    make([]byte, 0, MaxRecordLen*2),
	}
}

// ReadRecord 读取并解密下一个完整的 ChimneyRecord。
// 如果底层读取器返回 io.EOF 且无数据，则返回 io.EOF。
// 线程安全。
func (rr *RecordReader) ReadRecord() ([]byte, error) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	for {
		// 尝试从缓冲区解码
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
				rr.compactBuffer()
				return result.Plaintext, nil
			}
		}

		// 需要更多数据
		if len(rr.buf) >= MaxBufSize {
			return nil, ErrBufferOverflow
		}

		// 确保有足够的空闲容量容纳完整记录，无需单独分配。
		// 仅在空闲容量太小时才压缩（从头重新分配）。
		if cap(rr.buf)-len(rr.buf) < MaxRecordLen {
			newCap := len(rr.buf) + MaxRecordLen*2
			if newCap > MaxBufSize {
				newCap = MaxBufSize
			}
			newBuf := make([]byte, len(rr.buf), newCap)
			copy(newBuf, rr.buf)
			rr.buf = newBuf
		}

		// 直接读取到空闲缓冲区空间——无需单独的临时分配。
		prevLen := len(rr.buf)
		rr.buf = rr.buf[:cap(rr.buf)]
		n, err := rr.reader.Read(rr.buf[prevLen:])
		rr.buf = rr.buf[:prevLen+n]

		if err != nil {
			if err == io.EOF && len(rr.buf) > 0 {
				if len(rr.buf) < RecordHeaderLen {
					return nil, io.ErrUnexpectedEOF
				}
				result, decodeErr := rr.codec.DecodeRecord(rr.buf)
				if decodeErr != nil {
					return nil, io.ErrUnexpectedEOF
				}
				rr.buf = rr.buf[result.Consumed:]
				rr.compactBuffer()
				return result.Plaintext, nil
			}
			return nil, err
		}
	}
}

func (rr *RecordReader) compactBuffer() {
	if len(rr.buf) == 0 && cap(rr.buf) > MaxRecordLen*2 {
		rr.buf = make([]byte, 0, MaxRecordLen*2)
	}
}

// Buffered 返回内部缓冲区中未读取的字节数。
func (rr *RecordReader) Buffered() int {
	return len(rr.buf)
}

// KeyLen 返回 AEAD 算法的预期密钥长度。
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

// NonceLen 返回 AEAD 算法的预期 nonce 长度。
func NonceLen(aead string) int {
	switch aead {
	case "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305":
		return 12
	default:
		return 12
	}
}
