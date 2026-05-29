// Package h2engine implements HTTP/2 framing for the Chimney tunnel (Part III §2).
//
// After the swap, the internal payload of each ChimneyRecord is a stream of
// H2 frames. This package handles:
//   - H2 connection preface and SETTINGS exchange
//   - DATA frame encoding/decoding for tunnel data
//   - SETTINGS snapshot capture and replay
//   - Frame-level I/O on the record stream
//
// The H2 frames are "real" — they carry actual H2 semantics, providing:
//  1. Authentic record sizes (from the H2 frame structure)
//  2. Clean multiplexing (tunnel/padding/optional real content on separate streams)
//  3. Self-consistent flow control (WINDOW_UPDATE cadence)
package h2engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/shuffleman/chimney-protocol/internal/record"
)

// HTTP/2 frame types.
const (
	FrameData         uint8 = 0x0
	FrameHeaders      uint8 = 0x1
	FramePriority     uint8 = 0x2
	FrameRSTStream    uint8 = 0x3
	FrameSettings     uint8 = 0x4
	FramePushPromise  uint8 = 0x5
	FramePing         uint8 = 0x6
	FrameGoAway       uint8 = 0x7
	FrameWindowUpdate uint8 = 0x8
	FrameContinuation uint8 = 0x9
)

// HTTP/2 frame flags.
const (
	FlagEndStream  uint8 = 0x1
	FlagAck        uint8 = 0x1 // for SETTINGS and PING
	FlagEndHeaders uint8 = 0x4
	FlagPadded     uint8 = 0x8
	FlagPriority   uint8 = 0x20
)

// HTTP/2 error codes.
const (
	H2ErrNoError            uint32 = 0x0
	H2ErrProtocolError      uint32 = 0x1
	H2ErrInternalError      uint32 = 0x2
	H2ErrFlowControlError   uint32 = 0x3
	H2ErrSettingsTimeout    uint32 = 0x4
	H2ErrStreamClosed       uint32 = 0x5
	H2ErrFrameSize          uint32 = 0x6
	H2ErrRefusedStream      uint32 = 0x7
	H2ErrCancel             uint32 = 0x8
	H2ErrCompressionError   uint32 = 0x9
	H2ErrConnectError       uint32 = 0xa
	H2ErrEnhanceYourCalm    uint32 = 0xb
	H2ErrInadequateSecurity uint32 = 0xc
	H2ErrHTTP11Required     uint32 = 0xd
)

// HTTP/2 SETTINGS identifiers.
const (
	SettingHeaderTableSize      uint16 = 0x1
	SettingEnablePush           uint16 = 0x2
	SettingMaxConcurrentStreams uint16 = 0x3
	SettingInitialWindowSize    uint16 = 0x4
	SettingMaxFrameSize         uint16 = 0x5
	SettingMaxHeaderListSize    uint16 = 0x6
)

const (
	// H2ConnectionPreface is the client connection preface.
	H2ConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	// DefaultMaxFrameSize is the default maximum frame payload size (16 KiB).
	DefaultMaxFrameSize = 16384

	// FrameHeaderLen is the HTTP/2 frame header length.
	FrameHeaderLen = 9

	// DefaultSettingsFrameSize is the typical SETTINGS frame size
	// with 6 settings: 6 * 6 + 9 = 45 bytes.
	DefaultSettingsPayloadSize = 36 // 6 settings * 6 bytes each
)

var (
	// ErrFrameTooShort is returned when there's insufficient data for a frame header.
	ErrFrameTooShort = errors.New("h2engine: insufficient data for frame header")

	// ErrFrameSizeError is returned when a frame exceeds MaxFrameSize.
	ErrFrameSizeError = errors.New("h2engine: frame size exceeds maximum")

	// ErrInvalidPreface is returned when the client preface doesn't match.
	ErrInvalidPreface = errors.New("h2engine: invalid client preface")
)

// Settings represents HTTP/2 SETTINGS parameters.
// Values are stored as uint32; a nil pointer means "not set / use default".
type Settings struct {
	HeaderTableSize      *uint32
	EnablePush           *uint32
	MaxConcurrentStreams *uint32
	InitialWindowSize    *uint32
	MaxFrameSize         *uint32
	MaxHeaderListSize    *uint32

	// MaxFrameSizeActual is the effective max frame size (default or from settings).
	MaxFrameSizeActual uint32
}

// DefaultSettings returns Go's default-like settings.
// In production, these MUST be captured from the real site (§2.2).
func DefaultSettings() *Settings {
	headerTableSize := uint32(4096)
	enablePush := uint32(0) // Most servers disable push
	maxConcurrentStreams := uint32(100)
	initialWindowSize := uint32(65535) // Default per RFC 7540
	maxFrameSize := uint32(16384)
	maxHeaderListSize := uint32(uint32(1<<31) - 1)

	return &Settings{
		HeaderTableSize:      &headerTableSize,
		EnablePush:           &enablePush,
		MaxConcurrentStreams: &maxConcurrentStreams,
		InitialWindowSize:    &initialWindowSize,
		MaxFrameSize:         &maxFrameSize,
		MaxHeaderListSize:    &maxHeaderListSize,
		MaxFrameSizeActual:   16384,
	}
}

// SiteSettings holds captured SETTINGS from a real site.
type SiteSettings struct {
	SiteName   string
	Settings   *Settings
	RawCapture []byte // Raw SETTINGS frame bytes captured from the site
}

// EncodeSettings encodes the settings into a SETTINGS frame.
func (s *Settings) EncodeSettings(ack bool) []byte {
	var payload []byte

	if !ack {
		var buf bytes.Buffer
		writeSetting := func(id uint16, val uint32) {
			binary.Write(&buf, binary.BigEndian, id)
			binary.Write(&buf, binary.BigEndian, val)
		}

		if s.HeaderTableSize != nil {
			writeSetting(SettingHeaderTableSize, *s.HeaderTableSize)
		}
		if s.EnablePush != nil {
			writeSetting(SettingEnablePush, *s.EnablePush)
		}
		if s.MaxConcurrentStreams != nil {
			writeSetting(SettingMaxConcurrentStreams, *s.MaxConcurrentStreams)
		}
		if s.InitialWindowSize != nil {
			writeSetting(SettingInitialWindowSize, *s.InitialWindowSize)
		}
		if s.MaxFrameSize != nil {
			writeSetting(SettingMaxFrameSize, *s.MaxFrameSize)
		}
		if s.MaxHeaderListSize != nil {
			writeSetting(SettingMaxHeaderListSize, *s.MaxHeaderListSize)
		}

		payload = buf.Bytes()
	}

	// Build frame header
	frame := make([]byte, FrameHeaderLen+len(payload))
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	frame[3] = FrameSettings
	if ack {
		frame[4] = FlagAck
	} else {
		frame[4] = 0
	}
	binary.BigEndian.PutUint32(frame[5:9], 0) // Stream ID = 0 for SETTINGS
	copy(frame[FrameHeaderLen:], payload)

	return frame
}

// DecodeSettings decodes a SETTINGS frame payload into Settings values.
func DecodeSettings(payload []byte) (map[uint16]uint32, error) {
	settings := make(map[uint16]uint32)
	if len(payload)%6 != 0 {
		return nil, errors.New("h2engine: SETTINGS payload length must be multiple of 6")
	}
	for i := 0; i < len(payload); i += 6 {
		id := binary.BigEndian.Uint16(payload[i:])
		val := binary.BigEndian.Uint32(payload[i+2:])
		settings[id] = val
	}
	return settings, nil
}

// FrameHeader represents the 9-byte HTTP/2 frame header.
type FrameHeader struct {
	Length   uint32 // 24 bits
	Type     uint8
	Flags    uint8
	StreamID uint32 // 31 bits
}

// EncodeHeader encodes the frame header into 9 bytes.
func (fh *FrameHeader) EncodeHeader() []byte {
	buf := make([]byte, FrameHeaderLen)
	// Length: 24 bits
	buf[0] = byte(fh.Length >> 16)
	buf[1] = byte(fh.Length >> 8)
	buf[2] = byte(fh.Length)
	buf[3] = fh.Type
	buf[4] = fh.Flags
	// Stream ID: 31 bits + reserved bit
	binary.BigEndian.PutUint32(buf[5:9], fh.StreamID&0x7FFFFFFF)
	return buf
}

// DecodeFrameHeader decodes a 9-byte frame header.
func DecodeFrameHeader(data []byte) (*FrameHeader, error) {
	if len(data) < FrameHeaderLen {
		return nil, ErrFrameTooShort
	}
	fh := &FrameHeader{
		Length:   (uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])),
		Type:     data[3],
		Flags:    data[4],
		StreamID: binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF,
	}
	return fh, nil
}

// DataFrame encodes a DATA frame with the given payload.
// streamID must be non-zero. flags can include FlagEndStream.
func DataFrame(streamID uint32, flags uint8, payload []byte) []byte {
	frame := make([]byte, FrameHeaderLen+len(payload))
	// Length is 24 bits (3 bytes)
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	frame[3] = FrameData
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7FFFFFFF)
	copy(frame[FrameHeaderLen:], payload)
	return frame
}

// HeadersFrame encodes a HEADERS frame.
func HeadersFrame(streamID uint32, flags uint8, blockFragment []byte) []byte {
	frame := make([]byte, FrameHeaderLen+len(blockFragment))
	frame[0] = byte(len(blockFragment) >> 16)
	frame[1] = byte(len(blockFragment) >> 8)
	frame[2] = byte(len(blockFragment))
	frame[3] = FrameHeaders
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7FFFFFFF)
	copy(frame[FrameHeaderLen:], blockFragment)
	return frame
}

// WindowUpdateFrame encodes a WINDOW_UPDATE frame.
func WindowUpdateFrame(streamID uint32, increment uint32) []byte {
	frame := make([]byte, FrameHeaderLen+4)
	// 4-byte payload
	frame[0] = 0
	frame[1] = 0
	frame[2] = 4
	frame[3] = FrameWindowUpdate
	frame[4] = 0
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7FFFFFFF)
	binary.BigEndian.PutUint32(frame[9:], increment&0x7FFFFFFF)
	return frame
}

// RSTStreamFrame encodes an RST_STREAM frame.
func RSTStreamFrame(streamID uint32, errCode uint32) []byte {
	frame := make([]byte, FrameHeaderLen+4)
	frame[0] = 0
	frame[1] = 0
	frame[2] = 4
	frame[3] = FrameRSTStream
	frame[4] = 0
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7FFFFFFF)
	binary.BigEndian.PutUint32(frame[9:], errCode)
	return frame
}

// Engine manages the H2 framing layer over ChimneyRecords.
type Engine struct {
	settings    *Settings
	recordCodec *record.Codec

	// Stream state
	nextStreamID uint32
	streams      map[uint32]*Stream
	mu           sync.RWMutex

	// For reading/writing records
	recordReader *record.RecordReader
	recordWriter *record.RecordWriter

	// Internal buffer for frame accumulation
	readBuf  []byte
	writeBuf []byte
}

// Stream represents an H2 stream within the tunnel.
type Stream struct {
	ID        uint32
	State     StreamState
	Window    int32 // Flow control window
	RecvWindow int32
}

// StreamState represents the state of an H2 stream.
type StreamState uint8

const (
	StreamIdle StreamState = iota
	StreamOpen
	StreamHalfClosedLocal
	StreamHalfClosedRemote
	StreamClosed
)

// NewEngine creates a new H2 engine with the given settings and record codec.
func NewEngine(settings *Settings, codec *record.Codec) *Engine {
	if settings == nil {
		settings = DefaultSettings()
	}
	e := &Engine{
		settings:     settings,
		recordCodec:  codec,
		nextStreamID: 1, // Client-initiated streams start at 1
		streams:      make(map[uint32]*Stream),
		readBuf:      make([]byte, 0, DefaultMaxFrameSize*2),
		writeBuf:     make([]byte, 0, DefaultMaxFrameSize*2),
	}
	return e
}

// SetRecordIO sets the record reader and writer for frame I/O.
func (e *Engine) SetRecordIO(reader *record.RecordReader, writer *record.RecordWriter) {
	e.recordReader = reader
	e.recordWriter = writer
}

// InitiateAsClient performs the client-side H2 opening sequence:
//   1. Send preface + SETTINGS
//   2. Receive server SETTINGS
//   3. Send SETTINGS ACK
//   4. Receive SETTINGS ACK
func (e *Engine) InitiateAsClient() error {
	if e.recordWriter == nil {
		return errors.New("h2engine: record writer not set")
	}

	// Step 1: Send preface + SETTINGS
	preface := []byte(H2ConnectionPreface)
	settingsFrame := e.settings.EncodeSettings(false)

	combined := make([]byte, len(preface)+len(settingsFrame))
	copy(combined, preface)
	copy(combined[len(preface):], settingsFrame)

	if err := e.recordWriter.WriteRecord(combined); err != nil {
		return fmt.Errorf("h2engine: failed to send preface+SETTINGS: %w", err)
	}

	// Step 2: Receive server SETTINGS
	// (This would be handled by the event loop; simplified here)

	// Step 3 & 4: ACKs would be exchanged
	return nil
}

// AcceptAsServer performs the server-side H2 opening sequence:
//   1. Read and validate client preface
//   2. Read client SETTINGS
//   3. Send server SETTINGS
//   4. Send SETTINGS ACK
//   5. Read client SETTINGS ACK
func (e *Engine) AcceptAsServer() error {
	if e.recordReader == nil {
		return errors.New("h2engine: record reader not set")
	}

	// Step 1: Read preface + first SETTINGS (they come in one record typically)
	data, err := e.recordReader.ReadRecord()
	if err != nil {
		return fmt.Errorf("h2engine: failed to read client preface: %w", err)
	}

	if len(data) < len(H2ConnectionPreface) {
		return ErrInvalidPreface
	}

	preface := string(data[:len(H2ConnectionPreface)])
	if preface != H2ConnectionPreface {
		return ErrInvalidPreface
	}

	// Remaining data after preface is the client's SETTINGS frame
	remaining := data[len(H2ConnectionPreface):]

	// Parse client SETTINGS
	if len(remaining) >= FrameHeaderLen {
		fh, err := DecodeFrameHeader(remaining)
		if err == nil && fh.Type == FrameSettings {
			// Process client settings (optional: apply them)
			_, _ = DecodeSettings(remaining[FrameHeaderLen : FrameHeaderLen+fh.Length])
		}
	}

	// Step 3: Send server SETTINGS
	settingsFrame := e.settings.EncodeSettings(false)
	if err := e.recordWriter.WriteRecord(settingsFrame); err != nil {
		return fmt.Errorf("h2engine: failed to send server SETTINGS: %w", err)
	}

	// Step 4: Send SETTINGS ACK
	ackFrame := e.settings.EncodeSettings(true)
	if err := e.recordWriter.WriteRecord(ackFrame); err != nil {
		return fmt.Errorf("h2engine: failed to send SETTINGS ACK: %w", err)
	}

	return nil
}

// OpenStream opens a new stream for sending data.
// Returns the stream ID.
func (e *Engine) OpenStream() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()

	streamID := e.nextStreamID
	e.nextStreamID += 2 // Client-initiated streams are odd

	initialWindow := int32(65535)
	if e.settings.InitialWindowSize != nil {
		initialWindow = int32(*e.settings.InitialWindowSize)
	}

	stream := &Stream{
		ID:         streamID,
		State:      StreamOpen,
		Window:     initialWindow,
		RecvWindow: initialWindow,
	}
	e.streams[streamID] = stream
	return streamID
}

// WriteData writes data as DATA frames on the given stream.
// Data is automatically fragmented according to MaxFrameSize.
func (e *Engine) WriteData(streamID uint32, data []byte, endStream bool) error {
	e.mu.RLock()
	stream, exists := e.streams[streamID]
	maxFrameSize := e.settings.MaxFrameSizeActual
	e.mu.RUnlock()

	if !exists {
		// Auto-create remote-initiated streams (e.g., client streams on relay)
		e.mu.Lock()
		initialWindow := int32(65535)
		if e.settings.InitialWindowSize != nil {
			initialWindow = int32(*e.settings.InitialWindowSize)
		}
		e.streams[streamID] = &Stream{
			ID:         streamID,
			State:      StreamOpen,
			Window:     initialWindow,
			RecvWindow: initialWindow,
		}
		e.mu.Unlock()
		// Re-read under RLock to match the normal path
		e.mu.RLock()
		stream = e.streams[streamID]
		maxFrameSize = e.settings.MaxFrameSizeActual
		e.mu.RUnlock()
	}
	if stream.State != StreamOpen {
		return fmt.Errorf("h2engine: stream %d not in open state", streamID)
	}

	// Fragment data into frames
	offset := 0
	for offset < len(data) {
		chunkSize := int(maxFrameSize)
		if chunkSize > len(data)-offset {
			chunkSize = len(data) - offset
		}

		flags := uint8(0)
		isLast := offset+chunkSize >= len(data)
		if isLast && endStream {
			flags = FlagEndStream
		}

		frame := DataFrame(streamID, flags, data[offset:offset+chunkSize])
		if err := e.recordWriter.WriteRecord(frame); err != nil {
			return fmt.Errorf("h2engine: failed to write DATA frame: %w", err)
		}

		offset += chunkSize
	}

	if endStream {
		e.mu.Lock()
		stream.State = StreamHalfClosedLocal
		e.mu.Unlock()
	}

	return nil
}

// WriteRawFrame writes a pre-built frame directly to the record layer.
// Unlike WriteData, this does not wrap the data in a DATA frame — it sends
// the bytes as-is. Use for control frames (RST_STREAM, GOAWAY, etc.).
func (e *Engine) WriteRawFrame(frame []byte) error {
	if e.recordWriter == nil {
		return errors.New("h2engine: record writer not set")
	}
	return e.recordWriter.WriteRecord(frame)
}

// ReadFrame reads and returns the next H2 frame from the record stream.
// Returns (header, payload, error).
func (e *Engine) ReadFrame() (*FrameHeader, []byte, error) {
	for {
		// Try to parse a frame from readBuf
		if len(e.readBuf) >= FrameHeaderLen {
			fh, err := DecodeFrameHeader(e.readBuf)
			if err != nil {
				return nil, nil, err
			}
			if fh.Length > uint32(e.settings.MaxFrameSizeActual) {
				return nil, nil, ErrFrameSizeError
			}
			totalLen := FrameHeaderLen + int(fh.Length)
			if len(e.readBuf) >= totalLen {
				payload := make([]byte, fh.Length)
				copy(payload, e.readBuf[FrameHeaderLen:totalLen])
				e.readBuf = e.readBuf[totalLen:]
				return fh, payload, nil
			}
		}

		// Need more data
		record, err := e.recordReader.ReadRecord()
		if err != nil {
			return nil, nil, err
		}
		e.readBuf = append(e.readBuf, record...)
	}
}

// GenerateClientOpeningSequence generates the complete client opening sequence
// as it would appear after the swap (preface + SETTINGS + ACKs).
// This is used by the client to produce the initial records.
func GenerateClientOpeningSequence(settings *Settings) []byte {
	var buf bytes.Buffer
	buf.WriteString(H2ConnectionPreface)
	buf.Write(settings.EncodeSettings(false))
	return buf.Bytes()
}

// GenerateServerOpeningSequence generates the server-side opening sequence
// (SETTINGS + ACK).
func GenerateServerOpeningSequence(settings *Settings) []byte {
	var buf bytes.Buffer
	buf.Write(settings.EncodeSettings(false))
	buf.Write(settings.EncodeSettings(true))
	return buf.Bytes()
}

// ParsePrefaceAndSettings parses the client preface and initial SETTINGS from
// the first record payload after swap.
// Returns (settings map, remaining data, error).
func ParsePrefaceAndSettings(data []byte) (map[uint16]uint32, []byte, error) {
	if len(data) < len(H2ConnectionPreface) {
		return nil, nil, ErrInvalidPreface
	}
	if string(data[:len(H2ConnectionPreface)]) != H2ConnectionPreface {
		return nil, nil, ErrInvalidPreface
	}

	remaining := data[len(H2ConnectionPreface):]
	if len(remaining) < FrameHeaderLen {
		return nil, nil, ErrFrameTooShort
	}

	fh, err := DecodeFrameHeader(remaining)
	if err != nil {
		return nil, nil, err
	}
	if fh.Type != FrameSettings {
		return nil, nil, fmt.Errorf("h2engine: expected SETTINGS frame, got type 0x%x", fh.Type)
	}

	if len(remaining) < FrameHeaderLen+int(fh.Length) {
		return nil, nil, ErrFrameTooShort
	}

	settings, err := DecodeSettings(remaining[FrameHeaderLen : FrameHeaderLen+int(fh.Length)])
	if err != nil {
		return nil, nil, err
	}

	afterSettings := remaining[FrameHeaderLen+int(fh.Length):]
	return settings, afterSettings, nil
}

// StreamManager handles stream lifecycle for the H2 engine.
type StreamManager struct {
	streams      map[uint32]*Stream
	nextStreamID uint32
	mu           sync.RWMutex
}

// NewStreamManager creates a new StreamManager.
// isServer: if true, server-initiated streams (even IDs) are used.
func NewStreamManager(isServer bool) *StreamManager {
	sm := &StreamManager{
		streams: make(map[uint32]*Stream),
	}
	if isServer {
		sm.nextStreamID = 2 // Server-initiated streams are even
	} else {
		sm.nextStreamID = 1 // Client-initiated streams are odd
	}
	return sm
}

// CreateStream opens a new stream.
func (sm *StreamManager) CreateStream(initialWindow int32) *Stream {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	stream := &Stream{
		ID:         sm.nextStreamID,
		State:      StreamOpen,
		Window:     initialWindow,
		RecvWindow: initialWindow,
	}
	sm.streams[stream.ID] = stream
	sm.nextStreamID += 2
	return stream
}

// GetStream returns a stream by ID.
func (sm *StreamManager) GetStream(id uint32) (*Stream, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.streams[id]
	return s, ok
}

// CloseStream closes a stream.
func (sm *StreamManager) CloseStream(id uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.streams[id]; ok {
		s.State = StreamClosed
	}
}

// WindowUpdate applies a window update to a stream.
func (sm *StreamManager) WindowUpdate(id uint32, increment uint32) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.streams[id]
	if !ok {
		return fmt.Errorf("h2engine: stream %d not found for window update", id)
	}
	s.Window += int32(increment)
	return nil
}
