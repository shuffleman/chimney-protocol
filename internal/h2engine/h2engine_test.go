package h2engine

import (
	"bytes"
	"testing"

	"github.com/shuffleman/chimney-protocol/internal/record"
)

func TestDefaultSettings(t *testing.T) {
	s := DefaultSettings()
	if s == nil {
		t.Fatal("DefaultSettings returned nil")
	}
	if s.HeaderTableSize == nil {
		t.Fatal("HeaderTableSize is nil")
	}
	if *s.HeaderTableSize != 4096 {
		t.Errorf("HeaderTableSize = %d, want 4096", *s.HeaderTableSize)
	}
	if s.EnablePush == nil {
		t.Fatal("EnablePush is nil")
	}
	if *s.EnablePush != 0 {
		t.Errorf("EnablePush = %d, want 0", *s.EnablePush)
	}
	if s.MaxConcurrentStreams == nil {
		t.Fatal("MaxConcurrentStreams is nil")
	}
	if s.InitialWindowSize == nil {
		t.Fatal("InitialWindowSize is nil")
	}
	if s.MaxFrameSize == nil {
		t.Fatal("MaxFrameSize is nil")
	}
	if s.MaxHeaderListSize == nil {
		t.Fatal("MaxHeaderListSize is nil")
	}
}

func TestSettings_EncodeSettings(t *testing.T) {
	s := DefaultSettings()
	frame := s.EncodeSettings(false)

	if len(frame) < FrameHeaderLen {
		t.Fatalf("SETTINGS frame too short: %d bytes", len(frame))
	}

	// Check frame header
	fh, err := DecodeFrameHeader(frame)
	if err != nil {
		t.Fatalf("DecodeFrameHeader failed: %v", err)
	}
	if fh.Type != FrameSettings {
		t.Errorf("Frame type = 0x%x, want 0x%x (SETTINGS)", fh.Type, FrameSettings)
	}
	if fh.StreamID != 0 {
		t.Errorf("StreamID = %d, want 0", fh.StreamID)
	}
	if fh.Flags != 0 {
		t.Errorf("Flags = 0x%x, want 0", fh.Flags)
	}

	// Decode settings from payload
	settings, err := DecodeSettings(frame[FrameHeaderLen:])
	if err != nil {
		t.Fatalf("DecodeSettings failed: %v", err)
	}

	if len(settings) == 0 {
		t.Error("No settings decoded")
	}
}

func TestSettings_EncodeSettingsAck(t *testing.T) {
	s := DefaultSettings()
	frame := s.EncodeSettings(true)

	fh, _ := DecodeFrameHeader(frame)
	if fh.Type != FrameSettings {
		t.Error("Not a SETTINGS frame")
	}
	if fh.Flags&FlagAck == 0 {
		t.Error("ACK flag not set")
	}
	if fh.Length != 0 {
		t.Errorf("ACK frame payload length = %d, want 0", fh.Length)
	}
}

func TestDecodeFrameHeader(t *testing.T) {
	// Build a known frame header
	frame := make([]byte, FrameHeaderLen)
	frame[0] = 0x00
	frame[1] = 0x00
	frame[2] = 0x10 // Length = 16
	frame[3] = 0x0  // Type = DATA
	frame[4] = 0x1  // Flags = END_STREAM
	frame[5] = 0x00
	frame[6] = 0x00
	frame[7] = 0x00
	frame[8] = 0x01 // StreamID = 1

	fh, err := DecodeFrameHeader(frame)
	if err != nil {
		t.Fatalf("DecodeFrameHeader failed: %v", err)
	}
	if fh.Length != 16 {
		t.Errorf("Length = %d, want 16", fh.Length)
	}
	if fh.Type != FrameData {
		t.Errorf("Type = 0x%x, want 0x%x", fh.Type, FrameData)
	}
	if fh.Flags != 0x1 {
		t.Errorf("Flags = 0x%x, want 0x1", fh.Flags)
	}
	if fh.StreamID != 1 {
		t.Errorf("StreamID = %d, want 1", fh.StreamID)
	}
}

func TestDecodeFrameHeader_TooShort(t *testing.T) {
	_, err := DecodeFrameHeader([]byte{0x00, 0x00}) // too short
	if err != ErrFrameTooShort {
		t.Errorf("Expected ErrFrameTooShort, got %v", err)
	}
}

func TestDataFrame(t *testing.T) {
	payload := []byte("test payload data")
	streamID := uint32(5)
	flags := uint8(FlagEndStream)

	frame := DataFrame(streamID, flags, payload)

	if len(frame) != FrameHeaderLen+len(payload) {
		t.Errorf("Frame length = %d, want %d", len(frame), FrameHeaderLen+len(payload))
	}

	fh, err := DecodeFrameHeader(frame)
	if err != nil {
		t.Fatalf("DecodeFrameHeader failed: %v", err)
	}
	if fh.Type != FrameData {
		t.Errorf("Type = 0x%x, want 0x%x", fh.Type, FrameData)
	}
	if fh.Flags != flags {
		t.Errorf("Flags = 0x%x, want 0x%x", fh.Flags, flags)
	}
	if fh.StreamID != streamID {
		t.Errorf("StreamID = %d, want %d", fh.StreamID, streamID)
	}
	if fh.Length != uint32(len(payload)) {
		t.Errorf("Length = %d, want %d", fh.Length, len(payload))
	}

	// Check payload
	if !bytes.Equal(frame[FrameHeaderLen:], payload) {
		t.Error("Payload doesn't match")
	}
}

func TestHeadersFrame(t *testing.T) {
	blockFragment := []byte("header block")
	frame := HeadersFrame(1, FlagEndHeaders, blockFragment)

	fh, _ := DecodeFrameHeader(frame)
	if fh.Type != FrameHeaders {
		t.Errorf("Type = 0x%x, want HEADERS", fh.Type)
	}
	if fh.Flags != FlagEndHeaders {
		t.Errorf("Flags = 0x%x, want END_HEADERS", fh.Flags)
	}
}

func TestWindowUpdateFrame(t *testing.T) {
	frame := WindowUpdateFrame(1, 65535)

	fh, _ := DecodeFrameHeader(frame)
	if fh.Type != FrameWindowUpdate {
		t.Errorf("Type = 0x%x, want WINDOW_UPDATE", fh.Type)
	}
	if fh.Length != 4 {
		t.Errorf("Length = %d, want 4", fh.Length)
	}

	// Check increment value
	increment := uint32(frame[FrameHeaderLen])<<24 |
		uint32(frame[FrameHeaderLen+1])<<16 |
		uint32(frame[FrameHeaderLen+2])<<8 |
		uint32(frame[FrameHeaderLen+3])
	if increment != 65535 {
		t.Errorf("Increment = %d, want 65535", increment)
	}
}

func TestRSTStreamFrame(t *testing.T) {
	frame := RSTStreamFrame(5, H2ErrCancel)

	fh, _ := DecodeFrameHeader(frame)
	if fh.Type != FrameRSTStream {
		t.Errorf("Type = 0x%x, want RST_STREAM", fh.Type)
	}

	errCode := uint32(frame[FrameHeaderLen])<<24 |
		uint32(frame[FrameHeaderLen+1])<<16 |
		uint32(frame[FrameHeaderLen+2])<<8 |
		uint32(frame[FrameHeaderLen+3])
	if errCode != H2ErrCancel {
		t.Errorf("Error code = %d, want H2ErrCancel (%d)", errCode, H2ErrCancel)
	}
}

func TestDecodeSettings(t *testing.T) {
	// Build a settings payload with 2 settings
	payload := make([]byte, 12)
	// Setting 1: HEADER_TABLE_SIZE = 8192
	payload[0] = 0x00
	payload[1] = 0x01 // ID
	payload[2] = 0x00
	payload[3] = 0x00
	payload[4] = 0x20
	payload[5] = 0x00 // Value = 8192
	// Setting 2: MAX_CONCURRENT_STREAMS = 128
	payload[6] = 0x00
	payload[7] = 0x03 // ID
	payload[8] = 0x00
	payload[9] = 0x00
	payload[10] = 0x00
	payload[11] = 0x80 // Value = 128

	settings, err := DecodeSettings(payload)
	if err != nil {
		t.Fatalf("DecodeSettings failed: %v", err)
	}

	if len(settings) != 2 {
		t.Errorf("Decoded %d settings, want 2", len(settings))
	}
	if settings[SettingHeaderTableSize] != 8192 {
		t.Errorf("HEADER_TABLE_SIZE = %d, want 8192", settings[SettingHeaderTableSize])
	}
	if settings[SettingMaxConcurrentStreams] != 128 {
		t.Errorf("MAX_CONCURRENT_STREAMS = %d, want 128", settings[SettingMaxConcurrentStreams])
	}
}

func TestDecodeSettings_InvalidLength(t *testing.T) {
	_, err := DecodeSettings([]byte{0x00, 0x01, 0x00}) // 3 bytes, not multiple of 6
	if err == nil {
		t.Error("Expected error for invalid payload length")
	}
}

func TestGenerateClientOpeningSequence(t *testing.T) {
	s := DefaultSettings()
	seq := GenerateClientOpeningSequence(s)

	// Should start with preface
	preface := []byte(H2ConnectionPreface)
	if !bytes.HasPrefix(seq, preface) {
		t.Error("Opening sequence doesn't start with preface")
	}

	// Should contain SETTINGS frame after preface
	remaining := seq[len(preface):]
	if len(remaining) < FrameHeaderLen {
		t.Fatal("No SETTINGS frame after preface")
	}

	fh, err := DecodeFrameHeader(remaining)
	if err != nil {
		t.Fatalf("Failed to decode SETTINGS frame: %v", err)
	}
	if fh.Type != FrameSettings {
		t.Errorf("Expected SETTINGS frame, got type 0x%x", fh.Type)
	}
}

func TestGenerateServerOpeningSequence(t *testing.T) {
	s := DefaultSettings()
	seq := GenerateServerOpeningSequence(s)

	// Should contain SETTINGS + SETTINGS ACK
	if len(seq) < FrameHeaderLen*2 {
		t.Fatal("Server opening sequence too short")
	}

	// First frame: SETTINGS
	fh1, _ := DecodeFrameHeader(seq)
	if fh1.Type != FrameSettings {
		t.Errorf("First frame type = 0x%x, want SETTINGS", fh1.Type)
	}
	if fh1.Flags&FlagAck != 0 {
		t.Error("First SETTINGS should not have ACK")
	}

	// Second frame: SETTINGS ACK
	fh2, _ := DecodeFrameHeader(seq[FrameHeaderLen+int(fh1.Length):])
	if fh2.Type != FrameSettings {
		t.Errorf("Second frame type = 0x%x, want SETTINGS", fh2.Type)
	}
	if fh2.Flags&FlagAck == 0 {
		t.Error("Second SETTINGS should have ACK")
	}
}

func TestParsePrefaceAndSettings(t *testing.T) {
	s := DefaultSettings()
	seq := GenerateClientOpeningSequence(s)

	settings, remaining, err := ParsePrefaceAndSettings(seq)
	if err != nil {
		t.Fatalf("ParsePrefaceAndSettings failed: %v", err)
	}

	if len(settings) == 0 {
		t.Error("No settings parsed")
	}
	if remaining == nil {
		t.Error("Remaining is nil")
	}
}

func TestParsePrefaceAndSettings_InvalidPreface(t *testing.T) {
	_, _, err := ParsePrefaceAndSettings([]byte("invalid preface"))
	if err != ErrInvalidPreface {
		t.Errorf("Expected ErrInvalidPreface, got %v", err)
	}
}

func TestStreamManager(t *testing.T) {
	sm := NewStreamManager(false) // client-side

	// Create stream
	stream := sm.CreateStream(65535)
	if stream == nil {
		t.Fatal("CreateStream returned nil")
	}
	if stream.ID != 1 {
		t.Errorf("First stream ID = %d, want 1", stream.ID)
	}
	if stream.State != StreamOpen {
		t.Errorf("Stream state = %d, want StreamOpen", stream.State)
	}

	// Get stream
	got, ok := sm.GetStream(1)
	if !ok {
		t.Fatal("GetStream returned not found")
	}
	if got.ID != 1 {
		t.Errorf("Got stream ID = %d, want 1", got.ID)
	}

	// Create another stream
	stream2 := sm.CreateStream(65535)
	if stream2.ID != 3 {
		t.Errorf("Second stream ID = %d, want 3", stream2.ID)
	}

	// Close stream
	sm.CloseStream(1)
	got, _ = sm.GetStream(1)
	if got.State != StreamClosed {
		t.Errorf("Stream state after close = %d, want StreamClosed", got.State)
	}
}

func TestStreamManager_ServerSide(t *testing.T) {
	sm := NewStreamManager(true) // server-side

	stream := sm.CreateStream(65535)
	if stream.ID != 2 {
		t.Errorf("First server stream ID = %d, want 2", stream.ID)
	}
}

func TestStreamManager_WindowUpdate(t *testing.T) {
	sm := NewStreamManager(false)
	sm.CreateStream(65535)

	err := sm.WindowUpdate(1, 1000)
	if err != nil {
		t.Errorf("WindowUpdate failed: %v", err)
	}

	stream, _ := sm.GetStream(1)
	if stream.Window != 65535+1000 {
		t.Errorf("Window = %d, want %d", stream.Window, 65535+1000)
	}

	// Non-existent stream
	err = sm.WindowUpdate(999, 1000)
	if err == nil {
		t.Error("Expected error for non-existent stream")
	}
}

func TestNewEngine(t *testing.T) {
	// Create a mock record codec
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	codec, err := record.NewCodec(key, nonce)
	if err != nil {
		t.Fatalf("Failed to create codec: %v", err)
	}

	settings := DefaultSettings()
	engine := NewEngine(settings, codec)

	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
	if engine.settings != settings {
		t.Error("Settings not set correctly")
	}
	if engine.nextStreamID != 1 {
		t.Errorf("nextStreamID = %d, want 1", engine.nextStreamID)
	}
}

func TestFrameConstants(t *testing.T) {
	// Verify frame type constants
	if FrameData != 0x0 {
		t.Errorf("FrameData = 0x%x, want 0x0", FrameData)
	}
	if FrameHeaders != 0x1 {
		t.Errorf("FrameHeaders = 0x%x, want 0x1", FrameHeaders)
	}
	if FrameSettings != 0x4 {
		t.Errorf("FrameSettings = 0x%x, want 0x4", FrameSettings)
	}
	if FrameWindowUpdate != 0x8 {
		t.Errorf("FrameWindowUpdate = 0x%x, want 0x8", FrameWindowUpdate)
	}

	// Verify flag constants
	if FlagEndStream != 0x1 {
		t.Errorf("FlagEndStream = 0x%x, want 0x1", FlagEndStream)
	}
	if FlagEndHeaders != 0x4 {
		t.Errorf("FlagEndHeaders = 0x%x, want 0x4", FlagEndHeaders)
	}

	// Verify error codes
	if H2ErrNoError != 0x0 {
		t.Errorf("H2ErrNoError = %d, want 0", H2ErrNoError)
	}
	if H2ErrProtocolError != 0x1 {
		t.Errorf("H2ErrProtocolError = %d, want 1", H2ErrProtocolError)
	}

	// Verify settings IDs
	if SettingHeaderTableSize != 0x1 {
		t.Errorf("SettingHeaderTableSize = 0x%x, want 0x1", SettingHeaderTableSize)
	}
	if SettingMaxConcurrentStreams != 0x3 {
		t.Errorf("SettingMaxConcurrentStreams = 0x%x, want 0x3", SettingMaxConcurrentStreams)
	}
}

func BenchmarkEncodeSettings(b *testing.B) {
	s := DefaultSettings()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.EncodeSettings(false)
	}
}

func BenchmarkDecodeFrameHeader(b *testing.B) {
	frame := make([]byte, FrameHeaderLen)
	frame[0] = 0x00
	frame[1] = 0x00
	frame[2] = 0x10
	frame[3] = 0x0
	frame[4] = 0x1
	frame[5] = 0x00
	frame[6] = 0x00
	frame[7] = 0x00
	frame[8] = 0x01

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := DecodeFrameHeader(frame)
		if err != nil {
			b.Fatal(err)
		}
	}
}
