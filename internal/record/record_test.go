package record

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

func generateTestKey(t *testing.T) []byte {
	key := make([]byte, 16) // AES-128
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return key
}

func generateTestNonce(t *testing.T) []byte {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}
	return nonce
}

func TestNewCodec(t *testing.T) {
	key := generateTestKey(t)
	nonce := generateTestNonce(t)

	codec, err := NewCodec(key, nonce)
	if err != nil {
		t.Fatalf("NewCodec failed: %v", err)
	}
	if codec == nil {
		t.Fatal("NewCodec returned nil")
	}

	// Check initial sequence numbers
	if codec.sealer.Sequence() != 0 {
		t.Errorf("Initial sealer seq = %d, want 0", codec.sealer.Sequence())
	}
	if codec.opener.Sequence() != 0 {
		t.Errorf("Initial opener seq = %d, want 0", codec.opener.Sequence())
	}
}

func TestCodec_EncodeDecode(t *testing.T) {
	key := generateTestKey(t)
	nonce := generateTestNonce(t)

	_, err := NewCodec(key, nonce)
	if err != nil {
		t.Fatalf("NewCodec failed: %v", err)
	}

	// 使用各种负载大小进行测试
	testSizes := []int{
		0,     // 空
		1,     // 1 字节
		16,    // 一个块
		1024,  // 1 KiB
		16384, // 16 KiB（最大明文）
	}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			if _, err := io.ReadFull(rand.Reader, plaintext); err != nil && size > 0 {
				t.Fatalf("Failed to generate plaintext: %v", err)
			}

			// 为每个测试重置序列号
			codec2, _ := NewCodec(key, nonce)

			// 编码
			record := codec2.EncodeRecord(plaintext)

			// 验证记录结构
			if len(record) < RecordHeaderLen {
				t.Fatalf("Record too short: %d bytes", len(record))
			}
			if record[0] != RecordTypeApplicationData {
				t.Errorf("Record type = 0x%02x, want 0x%02x", record[0], RecordTypeApplicationData)
			}
			if record[1] != 0x03 || record[2] != 0x03 {
				t.Errorf("Record version = 0x%02x%02x, want 0x0303", record[1], record[2])
			}

			// 解码
			result, err := codec2.DecodeRecord(record)
			if err != nil {
				t.Fatalf("DecodeRecord failed: %v", err)
			}

			if !bytes.Equal(result.Plaintext, plaintext) {
				t.Errorf("Decoded plaintext doesn't match original:\ngot  %x\nwant %x", result.Plaintext, plaintext)
			}
			if result.Consumed != len(record) {
				t.Errorf("Consumed = %d, want %d", result.Consumed, len(record))
			}
		})
	}
}

func TestCodec_SequenceIncrement(t *testing.T) {
	key := generateTestKey(t)
	nonce := generateTestNonce(t)

	codec, _ := NewCodec(key, nonce)
	plaintext := []byte("test data")

	// 编码多条记录
	for i := 0; i < 5; i++ {
		_ = codec.EncodeRecord(plaintext)
	}

	// Sealer 序列号应为 5
	if codec.sealer.Sequence() != 5 {
		t.Errorf("Sealer seq after 5 encodes = %d, want 5", codec.sealer.Sequence())
	}
}

func TestCodec_DirectionalKeys(t *testing.T) {
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)
	nonce1 := generateTestNonce(t)
	nonce2 := generateTestNonce(t)

	// 客户端使用 key1 发送，key2 接收
	// 服务端使用 key2 发送，key1 接收
	clientCodec, err := NewCodecWithDirectionalKeys(key1, nonce1, key2, nonce2)
	if err != nil {
		t.Fatalf("NewCodecWithDirectionalKeys failed: %v", err)
	}

	serverCodec, err := NewCodecWithDirectionalKeys(key2, nonce2, key1, nonce1)
	if err != nil {
		t.Fatalf("NewCodecWithDirectionalKeys (server) failed: %v", err)
	}

	plaintext := []byte("hello directional keys")

	// 客户端编码
	record := clientCodec.EncodeRecord(plaintext)

	// 服务端解码
	result, err := serverCodec.DecodeRecord(record)
	if err != nil {
		t.Fatalf("Server decode failed: %v", err)
	}

	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Errorf("Round-trip failed:\ngot  %x\nwant %x", result.Plaintext, plaintext)
	}
}

func TestDecodeRecord_TooShort(t *testing.T) {
	key := generateTestKey(t)
	nonce := generateTestNonce(t)
	codec, _ := NewCodec(key, nonce)

	_, err := codec.DecodeRecord([]byte{0x17, 0x03, 0x03}) // only 3 bytes
	if err != ErrRecordTooShort {
		t.Errorf("Expected ErrRecordTooShort, got %v", err)
	}
}

func TestDecodeRecord_InvalidType(t *testing.T) {
	key := generateTestKey(t)
	nonce := generateTestNonce(t)
	codec, _ := NewCodec(key, nonce)

	// 创建一条错误类型的记录
	plaintext := []byte("test")
	record := codec.EncodeRecord(plaintext)
	record[0] = 0x16 // Change to handshake type

	// Need to re-encode with the modified type or test differently
	// 由于 EncodeRecord 始终使用 0x17，我们手动构造一条记录测试
	_, err := codec.DecodeRecord(record)
	// 因为我们篡改了附加数据，这应失败并返回 bad MAC
	if err == nil {
		t.Error("Expected error for tampered record type, got nil")
	}
}

func TestCounterNonce(t *testing.T) {
	nonce, err := NewCounterNonce(12)
	if err != nil {
		t.Fatalf("NewCounterNonce failed: %v", err)
	}

	// Nonce for seq=0
	n0 := nonce.Nonce(0)
	if len(n0) != 12 {
		t.Errorf("Nonce length = %d, want 12", len(n0))
	}

	// Nonce for seq=1 should be different
	n1 := nonce.Nonce(1)
	if bytes.Equal(n0, n1) {
		t.Error("Nonces for different sequence numbers should differ")
	}

	// Same seq → same nonce
	n0again := nonce.Nonce(0)
	if !bytes.Equal(n0, n0again) {
		t.Error("Nonce for same seq should be identical")
	}
}

func TestCounterNonce_InvalidSize(t *testing.T) {
	_, err := NewCounterNonce(8)
	if err == nil {
		t.Error("Expected error for invalid nonce size, got nil")
	}
}

func TestRecordWriter_RecordReader(t *testing.T) {
	key := generateTestKey(t)
	nonce := generateTestNonce(t)
	codec, _ := NewCodec(key, nonce)

	// 使用管道模拟网络
	pr, pw := io.Pipe()

	recWriter := NewRecordWriter(pw, codec)
	recReader := NewRecordReader(pr, codec)

	plaintext := []byte("round-trip test data")

	// 在后台写入
	go func() {
		if err := recWriter.WriteRecord(plaintext); err != nil {
			t.Errorf("WriteRecord failed: %v", err)
		}
		pw.Close()
	}()

	// 读取
	decoded, err := recReader.ReadRecord()
	if err != nil {
		t.Fatalf("ReadRecord failed: %v", err)
	}

	if !bytes.Equal(decoded, plaintext) {
		t.Errorf("Round-trip failed:\ngot  %x\nwant %x", decoded, plaintext)
	}
}

func TestRecordWriter_WriteErrorRollsBackSeq(t *testing.T) {
	key := generateTestKey(t)
	nonce := generateTestNonce(t)
	codec, _ := NewCodec(key, nonce)

	pr, pw := io.Pipe()
	recWriter := NewRecordWriter(pw, codec)

	// 成功写入一条记录并排空管道，使其不会阻塞。
	done := make(chan struct{})
	go func() {
		recReader := NewRecordReader(pr, codec)
		_, err := recReader.ReadRecord()
		if err != nil {
			t.Logf("ReadRecord error (expected): %v", err)
		}
		close(done)
	}()

	if err := recWriter.WriteRecord([]byte("record-0")); err != nil {
		t.Fatalf("WriteRecord failed: %v", err)
	}
	<-done

	seqAfter := codec.sealer.Sequence()
	if seqAfter != 1 {
		t.Fatalf("expected seq=1 after one write, got %d", seqAfter)
	}

	// 关闭管道以模拟传输故障。
	pw.Close()

	// 此写入将失败，因为管道已关闭。
	err := recWriter.WriteRecord([]byte("record-1"))
	if err == nil {
		t.Fatal("expected error after pipe close, got nil")
	}
	t.Logf("WriteRecord error: %v", err)

	// 计数器必须回滚——未写入任何字节。
	seqAfterFail := codec.sealer.Sequence()
	if seqAfterFail != 1 {
		t.Errorf("expected seq=1 after failed write (rolled back), got %d", seqAfterFail)
	}

	// 后续写入应返回损坏错误，而不触及计数器。
	err2 := recWriter.WriteRecord([]byte("record-2"))
	if err2 == nil {
		t.Fatal("expected broken-writer error on second attempt")
	}
	seqAfterBroken := codec.sealer.Sequence()
	if seqAfterBroken != 1 {
		t.Errorf("expected seq=1 after broken-writer rejection, got %d", seqAfterBroken)
	}
}

func TestKeyLen(t *testing.T) {
	tests := []struct {
		aead string
		want int
	}{
		{"AES-128-GCM", 16},
		{"AES-256-GCM", 32},
		{"ChaCha20-Poly1305", 32},
		{"unknown", 16}, // default
	}

	for _, tc := range tests {
		got := KeyLen(tc.aead)
		if got != tc.want {
			t.Errorf("KeyLen(%q) = %d, want %d", tc.aead, got, tc.want)
		}
	}
}

func TestNonceLen(t *testing.T) {
	tests := []struct {
		aead string
		want int
	}{
		{"AES-128-GCM", 12},
		{"AES-256-GCM", 12},
		{"ChaCha20-Poly1305", 12},
		{"unknown", 12}, // default
	}

	for _, tc := range tests {
		got := NonceLen(tc.aead)
		if got != tc.want {
			t.Errorf("NonceLen(%q) = %d, want %d", tc.aead, got, tc.want)
		}
	}
}

func BenchmarkEncodeRecord(b *testing.B) {
	key := generateTestKey(&testing.T{})
	nonce := generateTestNonce(&testing.T{})
	codec, _ := NewCodec(key, nonce)
	plaintext := make([]byte, 1024)
	rand.Reader.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = codec.EncodeRecord(plaintext)
	}
}

// TestRecordWriter_PipeStress 通过 io.Pipe 发送多个完整大小的记录
// 以隔离记录损坏是编解码器问题还是 TCP 特定问题。
// 记录大小匹配 H2 最大帧：16384 负载 + 9 H2 头部 = 16393 字节明文。
func TestRecordWriter_PipeStress(t *testing.T) {
	const numRecords = 100
	const plaintextSize = 16384 + 9 // full H2 DATA frame

	key := generateTestKey(t)
	nonce := generateTestNonce(t)
	codec, _ := NewCodec(key, nonce)
	// 为读取器创建新的编解码器——相同的密钥材料
	codec2, _ := NewCodec(key, nonce)

	pr, pw := io.Pipe()
	recWriter := NewRecordWriter(pw, codec)
	recReader := NewRecordReader(pr, codec2)

	// 准备明文
	plaintexts := make([][]byte, numRecords)
	for i := range plaintexts {
		p := make([]byte, plaintextSize)
		rand.Reader.Read(p)
		plaintexts[i] = p
	}

	errCh := make(chan error, 1)
	go func() {
		defer pw.Close()
		for i, pt := range plaintexts {
			if err := recWriter.WriteRecord(pt); err != nil {
				errCh <- fmt.Errorf("WriteRecord seq=%d: %w", i, err)
				return
			}
		}
	}()

	for i := 0; i < numRecords; i++ {
		decoded, err := recReader.ReadRecord()
		if err != nil {
			t.Fatalf("ReadRecord seq=%d: %v", i, err)
		}
		if !bytes.Equal(decoded, plaintexts[i]) {
			t.Fatalf("MISMATCH seq=%d: len(want)=%d len(got)=%d", i, len(plaintexts[i]), len(decoded))
		}
	}

	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

func BenchmarkDecodeRecord(b *testing.B) {
	key := generateTestKey(&testing.T{})
	nonce := generateTestNonce(&testing.T{})
	codec, _ := NewCodec(key, nonce)
	plaintext := make([]byte, 1024)
	rand.Reader.Read(plaintext)
	record := codec.EncodeRecord(plaintext)

	// 为解码创建新的编解码器
	codec2, _ := NewCodec(key, nonce)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := codec2.DecodeRecord(record)
		if err != nil {
			b.Fatal(err)
		}
	}
}
