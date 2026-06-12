// Package h2engine 实现 Chimney 隧道的 HTTP/2 帧处理（第三部分 §2）。
//
// 交换后，每个 ChimneyRecord 的内部负载成为 H2 帧的流。
// 本包处理：
//   - H2 连接前导和 SETTINGS 交换
//   - 隧道数据的 DATA 帧编码/解码
//   - SETTINGS 快照捕获与重放
//   - 记录流上的帧级 I/O
//
// H2 帧是“真实的”——它们携带实际的 H2 语义，提供：
//  1. 真实的记录大小（来自 H2 帧结构）
//  2. 清晰的多路复用（隧道/填充/可选真实内容在不同流上）
//  3. 自洽的流控（WINDOW_UPDATE 节奏）
package h2engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/record"
)

// HTTP/2 帧类型。
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

// HTTP/2 帧标志。
const (
	FlagEndStream  uint8 = 0x1
	FlagAck        uint8 = 0x1 // 用于 SETTINGS 和 PING
	FlagEndHeaders uint8 = 0x4
	FlagPadded     uint8 = 0x8
	FlagPriority   uint8 = 0x20
)

// HTTP/2 错误码。
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

// HTTP/2 SETTINGS 标识符。
const (
	SettingHeaderTableSize      uint16 = 0x1
	SettingEnablePush           uint16 = 0x2
	SettingMaxConcurrentStreams uint16 = 0x3
	SettingInitialWindowSize    uint16 = 0x4
	SettingMaxFrameSize         uint16 = 0x5
	SettingMaxHeaderListSize    uint16 = 0x6
)

const (
	// H2ConnectionPreface 是客户端连接前导。
	H2ConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	// DefaultMaxFrameSize 是默认的最大帧负载大小。
	// 64 KiB 相比 RFC 7540 默认的 16 KiB，将每字节 AEAD/系统调用开销降低了 4 倍。
	// iOS 客户端可通过 Settings 降低此值以减少每隧道内存占用。
	DefaultMaxFrameSize = 65536

	// FrameHeaderLen 是 HTTP/2 帧头长度。
	FrameHeaderLen = 9

	// DefaultSettingsFrameSize 是典型 SETTINGS 帧大小（含 6 个设置项：6 * 6 + 9 = 45 字节）。
	DefaultSettingsPayloadSize = 36 // 6 个设置项 * 每项 6 字节

	// PaddingStreamID 是用于填充帧的保留 H2 流 ID。
	// 此流上的填充 DATA 帧携带虚拟字节以达到记录大小目标。
	// 中继节点静默丢弃此流上的帧。
	// 值是一个大的奇数，以避免与正常流冲突。
	PaddingStreamID = 0x0FFFFFFF

	// DilutionStreamID 是用于真实内容稀释的保留 H2 流 ID。
	// 稀释 DATA 帧携带来自白名单站点的预录 HTTP 响应数据块，
	// 使流量在深度包检测下与真实浏览语义上无法区分。
	DilutionStreamID = 0x0FFFFFFD
)

var (
	// ErrFrameTooShort 在帧头数据不足时返回。
	ErrFrameTooShort = errors.New("h2engine: insufficient data for frame header")

	// ErrFrameSizeError 在帧超过 MaxFrameSize 时返回。
	ErrFrameSizeError = errors.New("h2engine: frame size exceeds maximum")

	// ErrInvalidPreface 在客户端前导不匹配时返回。
	ErrInvalidPreface = errors.New("h2engine: invalid client preface")
)

// Settings 表示 HTTP/2 SETTINGS 参数。
// 值存储为 uint32；nil 指针表示“未设置 / 使用默认值”。
type Settings struct {
	HeaderTableSize      *uint32
	EnablePush           *uint32
	MaxConcurrentStreams *uint32
	InitialWindowSize    *uint32
	MaxFrameSize         *uint32
	MaxHeaderListSize    *uint32

	// MaxFrameSizeActual 是有效的最大帧大小（默认值或来自设置项）。
	MaxFrameSizeActual uint32
}

// DefaultSettings 返回类似 Go 默认值的设置。
// 生产中，这些值必须从真实站点捕获（§2.2）。
func DefaultSettings() *Settings {
	headerTableSize := uint32(4096)
	enablePush := uint32(0) // 大多数服务器禁用推送
	maxConcurrentStreams := uint32(100)
	initialWindowSize := uint32(65535) // RFC 7540 默认值
	maxFrameSize := uint32(16384)      // 匹配 Chrome/Firefox 默认值（RFC 7540 默认值）
	maxHeaderListSize := uint32(uint32(1<<31) - 1)

	return &Settings{
		HeaderTableSize:      &headerTableSize,
		EnablePush:           &enablePush,
		MaxConcurrentStreams: &maxConcurrentStreams,
		InitialWindowSize:    &initialWindowSize,
		MaxFrameSize:         &maxFrameSize,
		MaxHeaderListSize:    &maxHeaderListSize,
		MaxFrameSizeActual:   maxFrameSize,
	}
}

// SiteSettings 保存从真实站点捕获的 SETTINGS。
type SiteSettings struct {
	SiteName   string
	Settings   *Settings
	RawCapture []byte // 从站点捕获的原始 SETTINGS 帧字节
}

// EncodeSettings 将设置编码为 SETTINGS 帧。
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

	// 构建帧头
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
	binary.BigEndian.PutUint32(frame[5:9], 0) // SETTINGS 的流 ID = 0
	copy(frame[FrameHeaderLen:], payload)

	return frame
}

// DecodeSettings 将 SETTINGS 帧负载解码为 Settings 值。
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

// FrameHeader 表示 9 字节的 HTTP/2 帧头。
type FrameHeader struct {
	Length   uint32 // 24 位
	Type     uint8
	Flags    uint8
	StreamID uint32 // 31 位
}

// EncodeHeader 将帧头编码为 9 字节。
func (fh *FrameHeader) EncodeHeader() []byte {
	buf := make([]byte, FrameHeaderLen)
	// Length: 24 位
	buf[0] = byte(fh.Length >> 16)
	buf[1] = byte(fh.Length >> 8)
	buf[2] = byte(fh.Length)
	buf[3] = fh.Type
	buf[4] = fh.Flags
	// Stream ID: 31 位 + 保留位
	binary.BigEndian.PutUint32(buf[5:9], fh.StreamID&0x7FFFFFFF)
	return buf
}

// DecodeFrameHeader 解码 9 字节的帧头。
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

// DataFrame 用给定的负载编码一个 DATA 帧。
// streamID 必须非零。flags 可包含 FlagEndStream。
func DataFrame(streamID uint32, flags uint8, payload []byte) []byte {
	frame := make([]byte, FrameHeaderLen+len(payload))
	// Length 是 24 位（3 字节）
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	frame[3] = FrameData
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7FFFFFFF)
	copy(frame[FrameHeaderLen:], payload)
	return frame
}

// PingFrame 编码一个 PING 帧(连接级,stream 0,8 字节 opaque 数据)。
// ack=true 时设置 ACK 标志(即 PONG,原样回显收到的 opaque)。
func PingFrame(opaque [8]byte, ack bool) []byte {
	var flags uint8
	if ack {
		flags = FlagAck
	}
	frame := make([]byte, FrameHeaderLen+8)
	frame[2] = 8 // length = 8
	frame[3] = FramePing
	frame[4] = flags
	// stream ID = 0(连接级)
	copy(frame[FrameHeaderLen:], opaque[:])
	return frame
}

// HeadersFrame 编码一个 HEADERS 帧。
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

// WindowUpdateFrame 编码一个 WINDOW_UPDATE 帧。
func WindowUpdateFrame(streamID uint32, increment uint32) []byte {
	frame := make([]byte, FrameHeaderLen+4)
	// 4 字节负载
	frame[0] = 0
	frame[1] = 0
	frame[2] = 4
	frame[3] = FrameWindowUpdate
	frame[4] = 0
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7FFFFFFF)
	binary.BigEndian.PutUint32(frame[9:], increment&0x7FFFFFFF)
	return frame
}

// RSTStreamFrame 编码一个 RST_STREAM 帧。
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

// Engine 管理 ChimneyRecord 上的 H2 帧层。
type Engine struct {
	settings    *Settings
	recordCodec *record.Codec

	// 流状态
	nextStreamID uint32
	streams      map[uint32]*Stream
	mu           sync.RWMutex

	// 读写记录
	recordReader *record.RecordReader
	recordWriter *record.RecordWriter

	// 用于帧累积的内部缓冲区
	readBuf  []byte
	writeBuf []byte
}

// Stream 表示隧道内的 H2 流。
type Stream struct {
	ID         uint32
	State      StreamState
	Window     int32 // 流控窗口
	RecvWindow int32
}

// StreamState 表示 H2 流的状态。
type StreamState uint8

const (
	StreamIdle StreamState = iota
	StreamOpen
	StreamHalfClosedLocal
	StreamHalfClosedRemote
	StreamClosed
)

// NewEngine 使用给定的设置和记录编解码器创建新的 H2 引擎。
func NewEngine(settings *Settings, codec *record.Codec) *Engine {
	if settings == nil {
		settings = DefaultSettings()
	}
	e := &Engine{
		settings:     settings,
		recordCodec:  codec,
		nextStreamID: 1, // 客户端发起的流从 1 开始
		streams:      make(map[uint32]*Stream),
		readBuf:      make([]byte, 0, DefaultMaxFrameSize*2),
		writeBuf:     make([]byte, 0, DefaultMaxFrameSize*2),
	}
	return e
}

// SetRecordIO 设置用于帧 I/O 的记录读取器和写入器。
func (e *Engine) SetRecordIO(reader *record.RecordReader, writer *record.RecordWriter) {
	e.recordReader = reader
	e.recordWriter = writer
}

// CodecSeqs 返回底层记录编解码器的当前密封器和开启器序列号。
// 用于隧道故障期间的诊断。
func (e *Engine) CodecSeqs() (sealerSeq, openerSeq uint64) {
	if e.recordCodec == nil {
		return 0, 0
	}
	return e.recordCodec.SealerSeq(), e.recordCodec.OpenerSeq()
}

// CodecTrails 返回密封器和开启器的操作轨迹，用于诊断。
func (e *Engine) CodecTrails() (sealerTrail, openerTrail string) {
	if e.recordCodec == nil {
		return "(no codec)", "(no codec)"
	}
	return e.recordCodec.SealerTrail(), e.recordCodec.OpenerTrail()
}

// InitiateAsClient 执行客户端侧 H2 开启序列：
//  1. 发送前导 + SETTINGS
//  2. 接收服务器 SETTINGS
//  3. 发送 SETTINGS ACK
//  4. 接收 SETTINGS ACK
func (e *Engine) InitiateAsClient() error {
	if e.recordWriter == nil {
		return errors.New("h2engine: record writer not set")
	}

	// 步骤 1：发送前导 + SETTINGS
	preface := []byte(H2ConnectionPreface)
	settingsFrame := e.settings.EncodeSettings(false)

	combined := make([]byte, len(preface)+len(settingsFrame))
	copy(combined, preface)
	copy(combined[len(preface):], settingsFrame)

	if err := e.recordWriter.WriteRecord(combined); err != nil {
		return fmt.Errorf("h2engine: failed to send preface+SETTINGS: %w", err)
	}

	// 步骤 2：接收服务器 SETTINGS
	//（这应由事件循环处理；此处简化）

	// 步骤 3 和 4：交换 ACK
	return nil
}

// AcceptAsServer 执行服务器侧 H2 开启序列：
//  1. 读取并验证客户端前导
//  2. 读取客户端 SETTINGS
//  3. 发送服务器 SETTINGS
//  4. 发送 SETTINGS ACK
//  5. 读取客户端 SETTINGS ACK
func (e *Engine) AcceptAsServer() error {
	if e.recordReader == nil {
		return errors.New("h2engine: record reader not set")
	}

	// 步骤 1：读取前导和第一个 SETTINGS（它们通常在一个记录中一起到达）
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

	// 前导之后的数据是客户端的 SETTINGS 帧
	remaining := data[len(H2ConnectionPreface):]

	// 解析客户端 SETTINGS 并尊重 MAX_FRAME_SIZE：中继节点不得发送
	// 超过客户端通告最大值的帧。
	if len(remaining) >= FrameHeaderLen {
		fh, err := DecodeFrameHeader(remaining)
		if err == nil && fh.Type == FrameSettings && len(remaining) >= FrameHeaderLen+int(fh.Length) {
			clientSettings, _ := DecodeSettings(remaining[FrameHeaderLen : FrameHeaderLen+int(fh.Length)])
			if clientMaxFrame, ok := clientSettings[SettingMaxFrameSize]; ok && clientMaxFrame < e.settings.MaxFrameSizeActual {
				e.settings.MaxFrameSizeActual = clientMaxFrame
			}
		}
	}

	// 步骤 3：发送服务器 SETTINGS
	settingsFrame := e.settings.EncodeSettings(false)
	if err := e.recordWriter.WriteRecord(settingsFrame); err != nil {
		return fmt.Errorf("h2engine: failed to send server SETTINGS: %w", err)
	}

	// 步骤 4：发送 SETTINGS ACK
	ackFrame := e.settings.EncodeSettings(true)
	if err := e.recordWriter.WriteRecord(ackFrame); err != nil {
		return fmt.Errorf("h2engine: failed to send SETTINGS ACK: %w", err)
	}

	return nil
}

// OpenStream 打开一个新的用于发送数据的流。
// 返回流 ID。
func (e *Engine) OpenStream() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()

	streamID := e.nextStreamID
	e.nextStreamID += 2 // 客户端发起的流为奇数

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

// WriteData 在指定流上将数据写入为 DATA 帧。
// 数据会根据 MaxFrameSize 自动分片。
func (e *Engine) WriteData(streamID uint32, data []byte, endStream bool) error {
	return e.WriteDataWithDeadline(streamID, data, endStream, time.Time{})
}

// WriteDataWithDeadline 与 WriteData 相同，但会把写截止时间传递到记录层。
func (e *Engine) WriteDataWithDeadline(streamID uint32, data []byte, endStream bool, deadline time.Time) error {
	e.mu.Lock()
	stream, exists := e.streams[streamID]
	if !exists {
		initialWindow := int32(65535)
		if e.settings.InitialWindowSize != nil {
			initialWindow = int32(*e.settings.InitialWindowSize)
		}
		stream = &Stream{
			ID:         streamID,
			State:      StreamOpen,
			Window:     initialWindow,
			RecvWindow: initialWindow,
		}
		e.streams[streamID] = stream
	}
	if stream.State != StreamOpen {
		e.mu.Unlock()
		return fmt.Errorf("h2engine: stream %d not in open state", streamID)
	}
	maxFrameSize := e.settings.MaxFrameSizeActual
	e.mu.Unlock()

	// 将数据分片为帧（I/O 在锁外进行）
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
		if err := e.recordWriter.WriteRecordWithDeadline(frame, deadline); err != nil {
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

// WriteRawFrame 将预构建的帧直接写入记录层。
// 与 WriteData 不同，它不将数据包裹在 DATA 帧中——
// 它按原样发送字节。用于控制帧（RST_STREAM、GOAWAY 等）。
func (e *Engine) WriteRawFrame(frame []byte) error {
	if e.recordWriter == nil {
		return errors.New("h2engine: record writer not set")
	}
	return e.recordWriter.WriteRecord(frame)
}

// WritePaddedRecord 将隧道数据写入 DATA 帧，可选地附加填充 DATA 帧，
// 使得合并后的明文达到 targetSize 字节。
//
// 这会生成一个包含两个帧的单个 ChimneyRecord，匹配流量配置文件的
// 目标大小。如果隧道 DATA 帧本身已 >= targetSize，则不添加填充。
//
// 中继节点静默丢弃 PaddingStreamID 上的帧。
func (e *Engine) WritePaddedRecord(streamID uint32, data []byte, targetSize uint16, endStream bool) error {
	return e.WritePaddedRecordWithDeadline(streamID, data, targetSize, endStream, time.Time{})
}

// WritePaddedRecordWithDeadline 与 WritePaddedRecord 相同，但会把写截止时间传递到记录层。
func (e *Engine) WritePaddedRecordWithDeadline(streamID uint32, data []byte, targetSize uint16, endStream bool, deadline time.Time) error {
	if e.recordWriter == nil {
		return errors.New("h2engine: record writer not set")
	}

	flags := uint8(0)
	if endStream {
		flags = FlagEndStream
	}
	tunnelFrame := DataFrame(streamID, flags, data)

	if len(tunnelFrame) >= int(targetSize) {
		// 隧道数据自身已达到目标大小——无需填充
		return e.recordWriter.WriteRecordWithDeadline(tunnelFrame, deadline)
	}

	// 构建填充帧以达到目标大小
	padLen := int(targetSize) - len(tunnelFrame) - FrameHeaderLen
	if padLen <= 0 {
		// 没有足够的空间用于有意义的填充帧；按原样发送隧道数据
		return e.recordWriter.WriteRecordWithDeadline(tunnelFrame, deadline)
	}

	paddingPayload := make([]byte, padLen)
	paddingFrame := DataFrame(PaddingStreamID, 0, paddingPayload)

	// 将两个帧合并为一个记录
	combined := make([]byte, len(tunnelFrame)+len(paddingFrame))
	copy(combined, tunnelFrame)
	copy(combined[len(tunnelFrame):], paddingFrame)

	return e.recordWriter.WriteRecordWithDeadline(combined, deadline)
}

// WritePadding 发送一个独立的填充记录，填充至 targetSize。
// 在空闲期间用于维持流量外观。
func (e *Engine) WritePadding(targetSize uint16) error {
	if e.recordWriter == nil {
		return errors.New("h2engine: record writer not set")
	}

	padPayloadLen := int(targetSize) - FrameHeaderLen
	if padPayloadLen <= 0 {
		padPayloadLen = 64 // 最小填充量
	}
	payload := make([]byte, padPayloadLen)
	frame := DataFrame(PaddingStreamID, 0, payload)
	return e.recordWriter.WriteRecord(frame)
}

// WriteCombinedRecord 将多个 H2 帧写入单个 ChimneyRecord。
// 这是填充的底层构建块——调用者组装隧道 DATA 帧和填充 DATA 帧，
// 然后将它们一起写入。
func (e *Engine) WriteCombinedRecord(frames ...[]byte) error {
	if e.recordWriter == nil {
		return errors.New("h2engine: record writer not set")
	}

	totalLen := 0
	for _, f := range frames {
		totalLen += len(f)
	}
	combined := make([]byte, totalLen)
	off := 0
	for _, f := range frames {
		off += copy(combined[off:], f)
	}
	return e.recordWriter.WriteRecord(combined)
}

// IsPaddingStream 返回流 ID 是否为保留的填充流。
// 中继节点在分发前使用此函数过滤掉填充帧。
func IsPaddingStream(streamID uint32) bool {
	return streamID == PaddingStreamID
}

// IsDilutionStream 返回流 ID 是否为保留的稀释流。
func IsDilutionStream(streamID uint32) bool {
	return streamID == DilutionStreamID
}

// IsReservedStream 返回任何保留（非隧道）流 ID 是否为真。
// 中继节点用于丢弃填充和稀释帧。
func IsReservedStream(streamID uint32) bool {
	return IsPaddingStream(streamID) || IsDilutionStream(streamID)
}

// WriteDilutionRecord 将预录的内容块作为稀释 DATA 帧写入，
// 与填充合并以在单个 ChimneyRecord 中达到 targetSize。
// 稀释帧携带语义内容（看起来像真实的 HTTP 响应），而不是随机字节。
func (e *Engine) WriteDilutionRecord(content []byte, targetSize uint16) error {
	if e.recordWriter == nil {
		return errors.New("h2engine: record writer not set")
	}

	dilutionFrame := DataFrame(DilutionStreamID, 0, content)

	if len(dilutionFrame) >= int(targetSize) {
		return e.recordWriter.WriteRecord(dilutionFrame)
	}

	// 使用填充流数据填充以达到目标
	padLen := int(targetSize) - len(dilutionFrame) - FrameHeaderLen
	if padLen <= 0 {
		return e.recordWriter.WriteRecord(dilutionFrame)
	}

	paddingPayload := make([]byte, padLen)
	paddingFrame := DataFrame(PaddingStreamID, 0, paddingPayload)

	combined := make([]byte, len(dilutionFrame)+len(paddingFrame))
	copy(combined, dilutionFrame)
	copy(combined[len(dilutionFrame):], paddingFrame)

	return e.recordWriter.WriteRecord(combined)
}

// ReadFrame 从记录流中读取并返回下一个 H2 帧。
// 返回（header, payload, error）。
func (e *Engine) ReadFrame() (*FrameHeader, []byte, error) {
	for {
		// 尝试从 readBuf 解析一个帧
		e.mu.Lock()
		if len(e.readBuf) >= FrameHeaderLen {
			fh, err := DecodeFrameHeader(e.readBuf)
			if err != nil {
				e.mu.Unlock()
				return nil, nil, err
			}
			if fh.Length > uint32(e.settings.MaxFrameSizeActual) {
				e.mu.Unlock()
				return nil, nil, ErrFrameSizeError
			}
			totalLen := FrameHeaderLen + int(fh.Length)
			if len(e.readBuf) >= totalLen {
				payload := make([]byte, fh.Length)
				copy(payload, e.readBuf[FrameHeaderLen:totalLen])
				e.readBuf = e.readBuf[totalLen:]
				e.compactReadBuffer()

				e.mu.Unlock()

				return fh, payload, nil
			}
		}
		e.mu.Unlock()

		// 需要更多数据——I/O 在锁外进行
		record, err := e.recordReader.ReadRecord()
		if err != nil {
			return nil, nil, err
		}
		e.mu.Lock()
		e.readBuf = append(e.readBuf, record...)
		e.mu.Unlock()
	}
}

func (e *Engine) compactReadBuffer() {
	if len(e.readBuf) == 0 && cap(e.readBuf) > DefaultMaxFrameSize*2 {
		e.readBuf = make([]byte, 0, DefaultMaxFrameSize*2)
	}
}

// GenerateClientOpeningSequence 生成交换后出现的完整客户端开启序列
// （前导 + SETTINGS + ACK）。
// 客户端使用此函数产生初始记录。
func GenerateClientOpeningSequence(settings *Settings) []byte {
	var buf bytes.Buffer
	buf.WriteString(H2ConnectionPreface)
	buf.Write(settings.EncodeSettings(false))
	return buf.Bytes()
}

// GenerateServerOpeningSequence 生成服务器侧开启序列
// （SETTINGS + ACK）。
func GenerateServerOpeningSequence(settings *Settings) []byte {
	var buf bytes.Buffer
	buf.Write(settings.EncodeSettings(false))
	buf.Write(settings.EncodeSettings(true))
	return buf.Bytes()
}

// ParsePrefaceAndSettings 从交换后的第一个记录负载中解析客户端前导和初始 SETTINGS。
// 返回（settings map, remaining data, error）。
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

// StreamManager 管理 H2 引擎的流生命周期。
type StreamManager struct {
	streams      map[uint32]*Stream
	nextStreamID uint32
	mu           sync.RWMutex
}

// NewStreamManager 创建一个新的 StreamManager。
// isServer：如果为 true，则使用服务器发起的流（偶数 ID）。
func NewStreamManager(isServer bool) *StreamManager {
	sm := &StreamManager{
		streams: make(map[uint32]*Stream),
	}
	if isServer {
		sm.nextStreamID = 2 // 服务器发起的流为偶数
	} else {
		sm.nextStreamID = 1 // 客户端发起的流为奇数
	}
	return sm
}

// CreateStream 打开一个新的流。
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

// GetStream 按 ID 返回一个流。
func (sm *StreamManager) GetStream(id uint32) (*Stream, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.streams[id]
	return s, ok
}

// CloseStream 关闭一个流。
func (sm *StreamManager) CloseStream(id uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.streams[id]; ok {
		s.State = StreamClosed
	}
}

// WindowUpdate 对流应用窗口更新。
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
