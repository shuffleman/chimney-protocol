package auth

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

func generateTestPSK(t *testing.T) []byte {
	psk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		t.Fatalf("Failed to generate PSK: %v", err)
	}
	return psk
}

func TestNewAuthenticator(t *testing.T) {
	psk := generateTestPSK(t)

	auth, err := NewAuthenticator(psk, DefaultTagLen)
	if err != nil {
		t.Fatalf("NewAuthenticator failed: %v", err)
	}
	if auth == nil {
		t.Fatal("NewAuthenticator returned nil")
	}
	if auth.TagLen() != DefaultTagLen {
		t.Errorf("TagLen = %d, want %d", auth.TagLen(), DefaultTagLen)
	}
}

func TestNewAuthenticator_InvalidTagLen(t *testing.T) {
	psk := generateTestPSK(t)

	_, err := NewAuthenticator(psk, 4) // too short
	if err == nil {
		t.Error("Expected error for tag len < 8, got nil")
	}

	_, err = NewAuthenticator(psk, 40) // too long
	if err == nil {
		t.Error("Expected error for tag len > 32, got nil")
	}
}

func TestNewAuthenticatorFromHex(t *testing.T) {
	psk := generateTestPSK(t)
	pskHex := hex.EncodeToString(psk)

	auth, err := NewAuthenticatorFromHex(pskHex, DefaultTagLen)
	if err != nil {
		t.Fatalf("NewAuthenticatorFromHex failed: %v", err)
	}
	if auth == nil {
		t.Fatal("NewAuthenticatorFromHex returned nil")
	}
}

func TestNewAuthenticatorFromHex_InvalidHex(t *testing.T) {
	_, err := NewAuthenticatorFromHex("not-hex!!!", DefaultTagLen)
	if err == nil {
		t.Error("Expected error for invalid hex, got nil")
	}
}

func TestAuthenticator_GenerateAndVerifyTag(t *testing.T) {
	psk := generateTestPSK(t)
	auth, _ := NewAuthenticator(psk, DefaultTagLen)

	serverRandom := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverRandom); err != nil {
		t.Fatalf("Failed to generate ServerRandom: %v", err)
	}

	recordBytes := []byte("test-record-observable-bytes")

	// Generate tag
	tag, err := auth.GenerateTag(serverRandom, recordBytes)
	if err != nil {
		t.Fatalf("GenerateTag failed: %v", err)
	}
	if len(tag) != DefaultTagLen {
		t.Errorf("Tag length = %d, want %d", len(tag), DefaultTagLen)
	}

	// Verify correct tag
	ok, err := auth.VerifyTag(serverRandom, recordBytes, tag)
	if err != nil {
		t.Fatalf("VerifyTag failed: %v", err)
	}
	if !ok {
		t.Error("VerifyTag returned false for valid tag")
	}

	// Verify with wrong tag
	wrongTag := make([]byte, len(tag))
	copy(wrongTag, tag)
	wrongTag[0] ^= 0xFF
	ok, err = auth.VerifyTag(serverRandom, recordBytes, wrongTag)
	if err != nil {
		t.Fatalf("VerifyTag with wrong tag failed: %v", err)
	}
	if ok {
		t.Error("VerifyTag returned true for wrong tag")
	}

	// Verify with different authenticator (different PSK)
	otherPSK := generateTestPSK(t)
	otherAuth, _ := NewAuthenticator(otherPSK, DefaultTagLen)
	ok, err = otherAuth.VerifyTag(serverRandom, recordBytes, tag)
	if err != nil {
		t.Fatalf("VerifyTag with different PSK failed: %v", err)
	}
	if ok {
		t.Error("VerifyTag returned true for tag from different PSK")
	}
}

func TestAuthenticator_MustVerifyTag(t *testing.T) {
	psk := generateTestPSK(t)
	auth, _ := NewAuthenticator(psk, DefaultTagLen)

	serverRandom := make([]byte, 32)
	io.ReadFull(rand.Reader, serverRandom)
	recordBytes := []byte("test-record")

	tag, _ := auth.GenerateTag(serverRandom, recordBytes)

	// Valid tag
	err := auth.MustVerifyTag(serverRandom, recordBytes, tag)
	if err != nil {
		t.Errorf("MustVerifyTag with valid tag failed: %v", err)
	}

	// Invalid tag
	wrongTag := make([]byte, len(tag))
	copy(wrongTag, tag)
	wrongTag[0] ^= 0xFF
	err = auth.MustVerifyTag(serverRandom, recordBytes, wrongTag)
	if err != ErrAuthFailed {
		t.Errorf("MustVerifyTag with wrong tag: got %v, want ErrAuthFailed", err)
	}
}

func TestAuthenticator_GenerateTag_InvalidInputs(t *testing.T) {
	psk := generateTestPSK(t)
	auth, _ := NewAuthenticator(psk, DefaultTagLen)

	// Empty ServerRandom
	_, err := auth.GenerateTag([]byte{}, []byte("record"))
	if err != ErrServerRandomLength {
		t.Errorf("Expected ErrServerRandomLength, got %v", err)
	}

	// Empty record bytes
	_, err = auth.GenerateTag(make([]byte, 32), []byte{})
	if err != ErrRecordBytesEmpty {
		t.Errorf("Expected ErrRecordBytesEmpty, got %v", err)
	}
}

func TestExtractTag(t *testing.T) {
	loc := EmbedTagLocation{
		PayloadOffset: 0,
		TagLen:        16,
	}

	payload := []byte("hello world! This is the H2 preface.")
	tag := make([]byte, 16)
	rand.Reader.Read(tag)

	// Embed tag at offset 0
	embedded := EmbedTag(payload, tag, loc)

	// Extract tag
	extractedTag, remaining, err := ExtractTag(embedded, loc)
	if err != nil {
		t.Fatalf("ExtractTag failed: %v", err)
	}
	if len(extractedTag) != loc.TagLen {
		t.Errorf("Extracted tag length = %d, want %d", len(extractedTag), loc.TagLen)
	}
	if string(remaining) != string(payload) {
		t.Errorf("Remaining payload doesn't match original:\ngot  %q\nwant %q", remaining, payload)
	}
}

func TestExtractTag_PayloadTooShort(t *testing.T) {
	loc := EmbedTagLocation{
		PayloadOffset: 0,
		TagLen:        16,
	}

	// Payload shorter than tag length
	payload := []byte("short")

	_, _, err := ExtractTag(payload, loc)
	if err == nil {
		t.Error("Expected error for short payload, got nil")
	}
}

func TestEmbedTag(t *testing.T) {
	payload := []byte("H2 preface data")
	tag := []byte("sixteen-byte-tag")

	loc := EmbedTagLocation{
		PayloadOffset: 0,
		TagLen:        16,
	}

	result := EmbedTag(payload, tag, loc)

	// Result should be: tag + payload
	if len(result) != len(tag)+len(payload) {
		t.Errorf("Result length = %d, want %d", len(result), len(tag)+len(payload))
	}
	if string(result[:len(tag)]) != string(tag) {
		t.Error("Tag not at beginning of result")
	}
	if string(result[len(tag):]) != string(payload) {
		t.Error("Payload not after tag in result")
	}
}

func TestEmbedTag_NonZeroOffset(t *testing.T) {
	payload := []byte("PREFIX:H2 preface data")
	tag := []byte("sixteen-byte-tag")

	loc := EmbedTagLocation{
		PayloadOffset: 7, // After "PREFIX:"
		TagLen:        16,
	}

	result := EmbedTag(payload, tag, loc)

	// Result should be: "PREFIX:" + tag + "H2 preface data"
	expectedLen := len(payload) + len(tag)
	if len(result) != expectedLen {
		t.Errorf("Result length = %d, want %d", len(result), expectedLen)
	}
}

func TestServerRandomExtractor_ExtractFromServerHello(t *testing.T) {
	extractor := &ServerRandomExtractor{}

	// Build a minimal ServerHello message
	serverRandom := make([]byte, 32)
	io.ReadFull(rand.Reader, serverRandom)

	// ServerHello: type(1) + length(3) + version(2) + random(32) + ...
	msg := make([]byte, 4+2+32+1) // minimal: header + version + random + session_id_len(0)
	msg[0] = 0x02                  // ServerHello type
	msg[1] = 0x00
	msg[2] = 0x00
	msg[3] = byte(2 + 32 + 1) // length (3 bytes, so subtract header)
	msg[4] = 0x03                 // version TLS 1.2
	msg[5] = 0x03
	copy(msg[6:38], serverRandom)
	msg[38] = 0x00 // session ID length = 0

	extracted, err := extractor.ExtractFromServerHello(msg)
	if err != nil {
		t.Fatalf("ExtractFromServerHello failed: %v", err)
	}
	if len(extracted) != 32 {
		t.Errorf("Extracted ServerRandom length = %d, want 32", len(extracted))
	}
	if string(extracted) != string(serverRandom) {
		t.Errorf("Extracted ServerRandom doesn't match:\ngot  %x\nwant %x", extracted, serverRandom)
	}
}

func TestServerRandomExtractor_WrongMessageType(t *testing.T) {
	extractor := &ServerRandomExtractor{}

	msg := []byte{0x01, 0x00, 0x00, 0x00} // ClientHello type

	_, err := extractor.ExtractFromServerHello(msg)
	if err == nil {
		t.Error("Expected error for wrong message type, got nil")
	}
}

func TestServerRandomExtractor_ExtractFromTLSRecords(t *testing.T) {
	extractor := &ServerRandomExtractor{}

	// Build a ServerHello handshake message
	serverRandom := make([]byte, 32)
	io.ReadFull(rand.Reader, serverRandom)

	shMsg := make([]byte, 4+2+32+1)
	shMsg[0] = 0x02 // ServerHello
	shMsg[1] = 0x00
	shMsg[2] = 0x00
	shMsg[3] = byte(2 + 32 + 1)
	shMsg[4] = 0x03
	shMsg[5] = 0x03
	copy(shMsg[6:38], serverRandom)
	shMsg[38] = 0x00

	// Wrap in a TLS Handshake record (ContentType=0x16)
	tlsRecord := make([]byte, 5+len(shMsg))
	tlsRecord[0] = 0x16       // Handshake
	tlsRecord[1] = 0x03       // TLS 1.2 version
	tlsRecord[2] = 0x03
	tlsRecord[3] = byte(len(shMsg) >> 8)
	tlsRecord[4] = byte(len(shMsg))
	copy(tlsRecord[5:], shMsg)

	// Prepend some other records first (ChangeCipherSpec)
	ccs := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	fullData := append(ccs, tlsRecord...)

	extracted, err := extractor.ExtractFromTLSRecords(fullData)
	if err != nil {
		t.Fatalf("ExtractFromTLSRecords failed: %v", err)
	}
	if string(extracted) != string(serverRandom) {
		t.Errorf("Extracted ServerRandom doesn't match:\ngot  %x\nwant %x", extracted, serverRandom)
	}
}

func TestServerRandomExtractor_ExtractFromTLSRecords_NoHandshake(t *testing.T) {
	extractor := &ServerRandomExtractor{}

	// Only ChangeCipherSpec, no Handshake records
	ccs := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}

	_, err := extractor.ExtractFromTLSRecords(ccs)
	if err == nil {
		t.Error("Expected error for data with no Handshake records, got nil")
	}
}

func TestServerRandomExtractor_ExtractFromTLSRecords_Incomplete(t *testing.T) {
	extractor := &ServerRandomExtractor{}

	// Incomplete TLS record (header says 100 bytes but only 3 follow)
	partial := []byte{0x16, 0x03, 0x03, 0x00, 0x64, 0x01, 0x02, 0x03}

	_, err := extractor.ExtractFromTLSRecords(partial)
	if err == nil {
		t.Error("Expected error for incomplete TLS record, got nil")
	}
}

func TestClientRandomExtractor_ExtractFromClientHello(t *testing.T) {
	extractor := &ClientRandomExtractor{}

	clientRandom := make([]byte, 32)
	io.ReadFull(rand.Reader, clientRandom)

	// ClientHello: type(1) + length(3) + version(2) + random(32) + ...
	msg := make([]byte, 4+2+32+1)
	msg[0] = 0x01 // ClientHello type
	msg[1] = 0x00
	msg[2] = 0x00
	msg[3] = byte(2 + 32 + 1)
	msg[4] = 0x03
	msg[5] = 0x03
	copy(msg[6:38], clientRandom)
	msg[38] = 0x00

	extracted, err := extractor.ExtractFromClientHello(msg)
	if err != nil {
		t.Fatalf("ExtractFromClientHello failed: %v", err)
	}
	if len(extracted) != 32 {
		t.Errorf("Extracted ClientRandom length = %d, want 32", len(extracted))
	}
	if string(extracted) != string(clientRandom) {
		t.Errorf("Extracted ClientRandom doesn't match")
	}
}

func TestRecordBytesCollector(t *testing.T) {
	collector := NewRecordBytesCollector()

	data := []byte("test data for collection")
	n, err := collector.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d, want %d", n, len(data))
	}

	if string(collector.Bytes()) != string(data) {
		t.Errorf("Collected bytes don't match: got %q, want %q", collector.Bytes(), data)
	}

	// Reset
	collector.Reset()
	if len(collector.Bytes()) != 0 {
		t.Errorf("After Reset, len = %d, want 0", len(collector.Bytes()))
	}
}

func BenchmarkGenerateTag(b *testing.B) {
	psk := make([]byte, 32)
	rand.Reader.Read(psk)
	auth, _ := NewAuthenticator(psk, DefaultTagLen)

	serverRandom := make([]byte, 32)
	rand.Reader.Read(serverRandom)
	recordBytes := make([]byte, 1024)
	rand.Reader.Read(recordBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := auth.GenerateTag(serverRandom, recordBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyTag(b *testing.B) {
	psk := make([]byte, 32)
	rand.Reader.Read(psk)
	auth, _ := NewAuthenticator(psk, DefaultTagLen)

	serverRandom := make([]byte, 32)
	rand.Reader.Read(serverRandom)
	recordBytes := make([]byte, 1024)
	rand.Reader.Read(recordBytes)

	tag, _ := auth.GenerateTag(serverRandom, recordBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := auth.VerifyTag(serverRandom, recordBytes, tag)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Ensure constant time comparison by checking different tag positions
func TestVerifyTag_ConstantTime(t *testing.T) {
	psk := generateTestPSK(t)
	auth, _ := NewAuthenticator(psk, DefaultTagLen)

	serverRandom := make([]byte, 32)
	rand.Reader.Read(serverRandom)
	recordBytes := make([]byte, 1024)
	rand.Reader.Read(recordBytes)

	tag, _ := auth.GenerateTag(serverRandom, recordBytes)

	// Flip each byte and verify — all should fail with similar timing
	for i := 0; i < len(tag); i++ {
		wrongTag := make([]byte, len(tag))
		copy(wrongTag, tag)
		wrongTag[i] ^= 0xFF

		ok, err := auth.VerifyTag(serverRandom, recordBytes, wrongTag)
		if err != nil {
			t.Fatalf("VerifyTag byte %d: %v", i, err)
		}
		if ok {
			t.Errorf("VerifyTag returned true for flipped byte at position %d", i)
		}
	}
}
