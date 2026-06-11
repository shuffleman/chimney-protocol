// Package chimney 导出一个 Dialer，用于通过 Chimney 中继建立连接。
// 它设计供 sing-box、Xray-core 或任何需要基于 Chimney 协议获得 net.Conn 的 Go 项目导入。
//
// 用法：
//
//	d, err := chimney.NewDialer(chimney.Config{
//	    RelayAddr:  "relay.example.com:443",
//	    SNI:        "real-site.com",
//	    PSK:        "your-64-char-hex-psk",
//	    Fingerprint: "chrome",
//	})
//	if err != nil { ... }
//	defer d.Close()
//
//	conn, err := d.DialContext(ctx, "tcp", "api.example.com:443")
//	// conn 是一个 net.Conn — 可像任何 TCP 连接一样使用。
//
// Dialer 维护到中继的 H2 连接池。每个连接拥有独立的 TCP socket 和帧调度 goroutine，
// 因此较高的 PoolSize 值可提高高并发工作负载的吞吐量。PoolSize 默认为 4；
// 设置为 1 进入单连接模式（资源占用更低）。
package chimney

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/auth"
	"github.com/shuffleman/chimney-protocol/internal/dilution"
	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/keyderiv"
	"github.com/shuffleman/chimney-protocol/internal/profile"
	"github.com/shuffleman/chimney-protocol/internal/record"
	"github.com/shuffleman/chimney-protocol/internal/relay"

	utls "github.com/refraction-networking/utls"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultConnectTimeout 是建立隧道的默认超时时间。
	DefaultConnectTimeout = 10 * time.Second

	// DefaultHandshakeTimeout 是 TLS + H2 握手的默认超时时间。
	DefaultHandshakeTimeout = 10 * time.Second

	// DefaultPoolSize 是默认的并行 H2 连接数。
	DefaultPoolSize = 4

	// DefaultTCPBufferSize 是每个隧道默认的 TCP 读写缓冲区大小。
	DefaultTCPBufferSize = 256 * 1024

	// DefaultStreamChannelBuffer 是每条流接收帧通道的默认缓冲深度。
	DefaultStreamChannelBuffer = 64

	// DefaultStealthRecordSize 是 stealth 模式的默认 TLS application_data 明文目标大小。
	DefaultStealthRecordSize = 896

	// DefaultStealthTunnelLifetime 是 stealth 模式下单条 tunnel 的默认软生命周期。
	DefaultStealthTunnelLifetime = 35 * time.Second
)

// Config 保存建立 Chimney 隧道的所有参数。
// RelayAddr、SNI 以及 PSK 或 UserID 为必填项；所有其他字段均有默认值。
// Config 可安全嵌入下游项目的配置结构体中。
type Config struct {
	// RelayAddr 是中继服务器地址（host:port）。必填项。
	RelayAddr string `yaml:"relay_addr" json:"relay_addr"`

	// SNI 是 TLS 服务器名称指示（Server Name Indication）——必须是白名单站点。必填项。
	SNI string `yaml:"sni" json:"sni"`

	// PSK 是预共享密钥（64 个十六进制字符 = 256 位）。当设置了 UserID 时为可选；
	// 在该模式下 PSK 通过 SHA256(UserID) 派生。
	PSK string `yaml:"psk,omitempty" json:"psk,omitempty"`

	// UserID 是多用户中继部署中的用户标识符（例如 UUID）。
	// 它被哈希为一个 4 字节的密钥提示，随认证标签一起发送。
	// 如果为空，默认为 "default"（单用户模式）。
	UserID string `yaml:"user_id,omitempty" json:"user_id,omitempty"`

	// TagLen 是认证标签长度（字节）（默认：16）。
	TagLen int `yaml:"tag_len,omitempty" json:"tag_len,omitempty"`

	// Fingerprint 是 uTLS ClientHello 指纹规格（默认："chrome"）。
	// 可用选项：chrome, firefox, safari, ios, edge, android, 360, qq,
	// randomized, golang — 可附加版本号（例如 "chrome-120"）。
	//
	// 支持轮换以分散 JA3 指纹(通用反检测,无需站点抓包)：
	//   - 逗号分隔列表，如 "chrome,firefox,edge" — 每条隧道随机选一个；
	//   - 关键字 "rotate" 或 "auto" — 展开为默认真实浏览器池并轮换。
	Fingerprint string `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`

	// ClientHelloFile 是精确指纹校准文件路径(由 cmd/calibrate 从 pcap 提取的
	// 真实 ClientHello 原始字节,hex 编码)。设置后优先于 Fingerprint:每条连接
	// 用 uTLS HelloCustom + ApplyPreset 复刻这条真实 ClientHello,使扩展数量/
	// 顺序、ALPN、JA3 与真实浏览器完全一致(而非通用预设的逼近)。
	ClientHelloFile string `yaml:"client_hello_file,omitempty" json:"client_hello_file,omitempty"`

	// ProfilePath 是可选的用于填充的流量配置文件 JSON。
	// 空字符串表示禁用填充。
	ProfilePath string `yaml:"profile_path,omitempty" json:"profile_path,omitempty"`

	// PaddingTarget 覆盖填充记录大小。0 表示使用配置文件分布。
	PaddingTarget int `yaml:"padding_target,omitempty" json:"padding_target,omitempty"`

	// StealthMode 启用内置流量塑形：默认记录大小 padding 与 tunnel 生命周期轮换。
	// 它不依赖外部 profile，用于降低小 record 与长连接行为指纹。
	StealthMode bool `yaml:"stealth_mode,omitempty" json:"stealth_mode,omitempty"`

	// StealthRecordSize 是 StealthMode 的记录目标大小。0 使用 DefaultStealthRecordSize。
	StealthRecordSize int `yaml:"stealth_record_size,omitempty" json:"stealth_record_size,omitempty"`

	// MaxTunnelLifetime 是单条 tunnel 的软生命周期。0 表示不按年龄轮换；
	// 开启 StealthMode 时默认为 DefaultStealthTunnelLifetime。
	MaxTunnelLifetime time.Duration `yaml:"max_tunnel_lifetime,omitempty" json:"max_tunnel_lifetime,omitempty"`

	// DilutionPath 是可选的用于稀释流的内容块 JSON。
	// 空字符串表示禁用稀释。
	DilutionPath string `yaml:"dilution_path,omitempty" json:"dilution_path,omitempty"`

	// ConnectTimeout 是 TCP 连接超时时间（默认：10 秒）。
	ConnectTimeout time.Duration `yaml:"connect_timeout,omitempty" json:"connect_timeout,omitempty"`

	// HandshakeTimeout 是 TLS + H2 握手超时时间（默认：10 秒）。
	HandshakeTimeout time.Duration `yaml:"handshake_timeout,omitempty" json:"handshake_timeout,omitempty"`

	// PoolSize 是到中继的并行 H2 连接数（默认：4）。
	// 较高的值通过在多个 TCP socket 间并行分发帧来提高高并发下的吞吐量。
	// 设置为 1 进入单连接模式（资源占用最低，适用于低并发场景）。
	PoolSize int `yaml:"pool_size,omitempty" json:"pool_size,omitempty"`

	// TCPBufferSize 设置每个隧道连接的 TCP 读写缓冲区大小（字节）（默认：262144 = 256 KiB）。
	// 在 iOS 等内存受限的平台上，可减少到 65536 以每个隧道节省约 384 KiB 内存。
	TCPBufferSize int `yaml:"tcp_buffer_size,omitempty" json:"tcp_buffer_size,omitempty"`

	// StreamChannelBuffer 是每条流接收帧通道的缓冲深度（默认：64）。
	// 高并发下内存 ≈ 并发流数 × 此值 × 帧大小;iOS 等内存受限环境可降到 16~32。
	// 越大对突发吞吐更友好,越小越省内存。
	StreamChannelBuffer int `yaml:"stream_channel_buffer,omitempty" json:"stream_channel_buffer,omitempty"`

	// MaxConcurrentStreams 限制整个 Dialer 同时打开的流数（0 = 不限）。
	// 在内存受限环境(iOS Network Extension ~50MB)下硬性封顶内存:
	// 内存上限 ≈ MaxConcurrentStreams × 每流缓冲。超限时 DialContext 阻塞等待空位。
	MaxConcurrentStreams int `yaml:"max_concurrent_streams,omitempty" json:"max_concurrent_streams,omitempty"`

	// DialContext 可选:自定义到中继的 TCP 拨号。设置后用它替代默认
	// net.DialTimeout —— 传入 sing-box/Xray 等宿主的 interface-aware dialer,
	// 使连接绑定到正确网卡,并在网络切换(如 iOS WiFi↔蜂窝)时由宿主重绑/
	// 重拨,从而避免切网断流。不可由 YAML/JSON 配置(运行期注入)。
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error) `yaml:"-" json:"-"`
}

// DefaultConfig 返回一个填充了库默认值的 Config。
func DefaultConfig() Config {
	return Config{
		TagLen:           auth.DefaultTagLen,
		Fingerprint:      "chrome",
		ConnectTimeout:   DefaultConnectTimeout,
		HandshakeTimeout: DefaultHandshakeTimeout,
		PoolSize:         DefaultPoolSize,
		TCPBufferSize:    DefaultTCPBufferSize,
	}
}

// ConfigFromYAML 从 YAML 解析 Chimney 客户端库配置，应用默认值并验证。
// 适用于希望将 Chimney 作为传输层嵌入而无需导入内部包的下游项目。
func ConfigFromYAML(data []byte) (Config, error) {
	config := DefaultConfig()
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("chimney: parse config: %w", err)
	}
	if err := config.Normalize(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// LoadConfigFile 从 YAML 文件加载 Chimney 客户端库配置。
func LoadConfigFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("chimney: read config: %w", err)
	}
	return ConfigFromYAML(data)
}

// Normalize 应用默认值，在需要时从 UserID 派生 PSK，并验证配置。
// 当下游项目手动构造 Config 时此方法很有用。
func (c *Config) Normalize() error {
	if c.TagLen == 0 {
		c.TagLen = auth.DefaultTagLen
	}
	if c.Fingerprint == "" {
		c.Fingerprint = "chrome"
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = DefaultConnectTimeout
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if c.PoolSize <= 0 {
		c.PoolSize = DefaultPoolSize
	}
	if c.TCPBufferSize <= 0 {
		c.TCPBufferSize = DefaultTCPBufferSize
	}
	if c.StreamChannelBuffer <= 0 {
		c.StreamChannelBuffer = DefaultStreamChannelBuffer
	}
	if c.MaxConcurrentStreams < 0 {
		c.MaxConcurrentStreams = 0
	}
	if c.StealthMode {
		if c.StealthRecordSize <= 0 {
			c.StealthRecordSize = DefaultStealthRecordSize
		}
		if c.MaxTunnelLifetime == 0 {
			c.MaxTunnelLifetime = DefaultStealthTunnelLifetime
		}
	}

	if c.RelayAddr == "" {
		return fmt.Errorf("chimney: relay_addr is required")
	}
	if c.SNI == "" {
		return fmt.Errorf("chimney: sni is required")
	}
	if c.PSK == "" {
		if c.UserID == "" {
			return fmt.Errorf("chimney: psk or user_id is required")
		}
		c.PSK = hex.EncodeToString(auth.DerivePSKFromID(c.UserID))
	}
	if _, err := hex.DecodeString(c.PSK); err != nil {
		return fmt.Errorf("chimney: psk must be hex: %w", err)
	}
	if len(c.PSK) != 64 {
		return fmt.Errorf("chimney: psk must be 64 hex characters")
	}
	if c.TagLen < 8 || c.TagLen > 32 {
		return fmt.Errorf("chimney: tag_len must be between 8 and 32")
	}
	if c.PaddingTarget < 0 {
		return fmt.Errorf("chimney: padding_target must be >= 0")
	}
	if c.StealthRecordSize < 0 {
		return fmt.Errorf("chimney: stealth_record_size must be >= 0")
	}
	if c.MaxTunnelLifetime < 0 {
		return fmt.Errorf("chimney: max_tunnel_lifetime must be >= 0")
	}
	if c.ClientHelloFile != "" {
		// 精确校准:文件须可读且能重建出有效 spec(尽早暴露错误)。
		raw, err := loadClientHelloRaw(c.ClientHelloFile)
		if err != nil {
			return err
		}
		if _, err := buildClientHelloSpec(raw); err != nil {
			return err
		}
	} else if err := validateFingerprintSpec(c.Fingerprint); err != nil {
		return fmt.Errorf("chimney: %w", err)
	}
	return nil
}

// tunnel 是到中继的单个 H2 连接。Dialer 维护一个由这些 tunnel 组成的连接池，
// 以在高并发下并行分发帧。
type tunnel struct {
	rawConn   net.Conn
	h2Eng     *h2engine.Engine
	recReader *record.RecordReader
	recWriter *record.RecordWriter
	prof      *profile.Model
	padTarget int
	stealth   trafficShaper
	dilution  *dilution.Provider
	chanBuf   int // 每条流接收通道的缓冲深度
	bornAt    time.Time
	expiresAt time.Time

	mu        sync.Mutex
	streams   map[uint32]chan *streamFrame
	quit      chan struct{}
	dead      chan struct{}
	pong      chan struct{} // 收到 PONG(PING+ACK)时收到信号,供 ping() 探活
	lastRecv  atomic.Int64  // 最近一次成功读到帧的 unixnano,用于空闲探活
	closed    bool
	lastError error // 当 dispatchFrames 因读取错误退出时设置
}

// ping 在隧道上发送一个 PING 并等待 PONG,用于探测隧道是否存活
// (独立于后端连接速度)。返回是否在 timeout 内收到 PONG。
func (t *tunnel) ping(timeout time.Duration) bool {
	// 清空可能滞留的旧 PONG。
	select {
	case <-t.pong:
	default:
	}
	var op [8]byte
	binary.BigEndian.PutUint64(op[:], uint64(time.Now().UnixNano()))
	if err := t.h2Eng.WriteRawFrame(h2engine.PingFrame(op, false)); err != nil {
		return false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-t.pong:
		return true
	case <-t.dead:
		return false
	case <-t.quit:
		return false
	case <-timer.C:
		return false
	}
}

// LastError 返回导致 dispatchFrames 退出的错误（如有）。
func (t *tunnel) LastError() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastError
}

// CodecTrails 返回 H2 引擎记录编解码器的密封器和开启器踪迹。
func (t *tunnel) CodecTrails() (sealerTrail, openerTrail string) {
	return t.h2Eng.CodecTrails()
}

// CodecSeqs 返回当前的密封器和开启器序列号。
func (t *tunnel) CodecSeqs() (sealerSeq, openerSeq uint64) {
	return t.h2Eng.CodecSeqs()
}

// Dialer 维护到 Chimney 中继的 H2 连接池。
// 多个 goroutine 可同时调用 DialContext；调用会在连接池中轮询分配。
type Dialer struct {
	config Config
	pool   []*tunnel
	next   atomic.Uint32
	mu     sync.Mutex
	closed bool

	// streamSem 限制同时打开的流数(MaxConcurrentStreams);nil 表示不限。
	streamSem chan struct{}

	// healthStop 停止后台健康检查 goroutine。
	healthStop chan struct{}

	prof     *profile.Model
	dilution *dilution.Provider
	dialNew  func(Config, *profile.Model, *dilution.Provider) (*tunnel, error)
}

// healthCheckInterval 是后台健康检查的周期。死链会在此周期内被主动重建,
// 而非等到下次 DialContext(惰性),从而在网络切换/抖动后秒级自愈。
const healthCheckInterval = 2500 * time.Millisecond

// pingIdleThreshold 是隧道空闲多久后才发 PING 探活。仅对空闲隧道探活:活跃
// 隧道有数据帧即证明存活,不必 ping(也避免给所有隧道周期性 PING 形成指纹)。
// 这与 http2.Transport.ReadIdleTimeout / sing-mux 的做法一致,只是阈值更短以
// 更快发现切网后"黑洞"的假死隧道。
const pingIdleThreshold = 5 * time.Second

// pingTimeout 是等待 PONG 的时间;超时即判隧道假死。
const pingTimeout = 2500 * time.Millisecond

// healthLoop 周期性扫描连接池,立即重建已死的隧道(经宿主 dialer 落到当前网卡)。
func (d *Dialer) healthLoop() {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.healthStop:
			return
		case <-ticker.C:
			d.mu.Lock()
			if d.closed {
				d.mu.Unlock()
				return
			}
			poolLen := len(d.pool)
			d.mu.Unlock()
			for i := 0; i < poolLen; i++ {
				select {
				case <-d.healthStop:
					return
				default:
				}
				d.reviveIfDead(uint32(i)) // 已死 → 重建
				d.pingIfIdle(uint32(i))   // 存活但空闲 → PING 探活,假死即拆除
			}
		}
	}
}

// reviveIfDead 仅当 pool[idx] 已死时主动重建(存活/空闲轮换的隧道不动)。
func (d *Dialer) reviveIfDead(idx uint32) {
	d.mu.Lock()
	if d.closed || int(idx) >= len(d.pool) {
		d.mu.Unlock()
		return
	}
	t := d.pool[idx]
	d.mu.Unlock()

	select {
	case <-t.dead:
		// 已死 → 重建(ensureTunnel 内部处理加锁与重新检查)。
		_, _ = d.ensureTunnel(idx)
	default:
		// 存活,保持不动。
	}
}

// pingIfIdle 对空闲存活隧道做 PING 探活:无 PONG(假死,如切网黑洞)即主动
// 拆除,下个健康检查周期由 reviveIfDead 重建。活跃隧道(近期有帧)跳过。
func (d *Dialer) pingIfIdle(idx uint32) {
	d.mu.Lock()
	if d.closed || int(idx) >= len(d.pool) {
		d.mu.Unlock()
		return
	}
	t := d.pool[idx]
	d.mu.Unlock()

	select {
	case <-t.dead:
		return // 已死,交给 reviveIfDead
	default:
	}
	if time.Since(time.Unix(0, t.lastRecv.Load())) < pingIdleThreshold {
		return // 近期有活动,无需探活
	}
	if !t.ping(pingTimeout) {
		go t.closeTunnel() // 假死 → 拆除,触发重建
	}
}

// streamChanBuf 返回每条流接收通道的缓冲深度。
func (d *Dialer) streamChanBuf() int {
	if d.config.StreamChannelBuffer > 0 {
		return d.config.StreamChannelBuffer
	}
	return DefaultStreamChannelBuffer
}

// Diagnostics 返回连接池中所有隧道的诊断信息。
func (d *Dialer) Diagnostics() string {
	var b strings.Builder
	for i, t := range d.pool {
		sealerSeq, openerSeq := t.CodecSeqs()
		sealerTrail, openerTrail := t.CodecTrails()
		fmt.Fprintf(&b, "=== Tunnel %d ===\n", i)
		fmt.Fprintf(&b, "sealer_seq=%d opener_seq=%d\n", sealerSeq, openerSeq)
		fmt.Fprintf(&b, "sealer trail:\n%s\n", sealerTrail)
		fmt.Fprintf(&b, "opener trail:\n%s\n", openerTrail)
		if le := t.LastError(); le != nil {
			fmt.Fprintf(&b, "lastError: %v\n", le)
		}
	}
	return b.String()
}

// streamFrame 是为特定 H2 流接收的帧。
type streamFrame struct {
	fh      *h2engine.FrameHeader
	payload []byte
}

// writeBufPool 复用 writeBufSize 字节的写入缓冲区(覆盖单个 TCP 分片帧)。
// 更大的写入(大 UDP 数据报)回退到堆分配。
var writeBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, writeBufSize)
		return &buf
	},
}

// streamConn 将单个 H2 流封装为 net.Conn。
type streamConn struct {
	t        *tunnel
	streamID uint32
	ch       chan *streamFrame
	cmd      byte // TCP 流使用 cmdTCP，UDP 流使用 cmdUDP

	readMu  sync.Mutex
	readBuf []byte // H2 帧载荷部分读取后的剩余数据

	closeOnce sync.Once
	closed    chan struct{}
	onRelease func() // Close 时调用一次,用于释放 Dialer 的并发流配额

	deadlineMu          sync.Mutex
	readDeadline        time.Time
	writeDeadline       time.Time
	readDeadlineChanged chan struct{}
}

type trafficShaper struct {
	recordSize int
}

func newTrafficShaper(config Config) trafficShaper {
	if config.StealthMode {
		size := config.StealthRecordSize
		if size <= 0 {
			size = DefaultStealthRecordSize
		}
		return trafficShaper{recordSize: size}
	}
	if config.PaddingTarget > 0 {
		return trafficShaper{recordSize: config.PaddingTarget}
	}
	return trafficShaper{}
}

func (s trafficShaper) targetSize(prof *profile.Model) uint16 {
	size := s.recordSize
	if size <= 0 && prof != nil {
		size = int(prof.RecordSize())
	}
	if size <= 0 {
		return 0
	}
	if size > 65535 {
		size = 65535
	}
	return uint16(size)
}

func writeShapedData(e *h2engine.Engine, streamID uint32, data []byte, targetSize uint16, endStream bool) error {
	if targetSize > 0 {
		return e.WritePaddedRecord(streamID, data, targetSize, endStream)
	}
	return e.WriteData(streamID, data, endStream)
}

func jitterTunnelLifetime(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	span := base / 5
	if span <= 0 {
		return base
	}
	return base - span + time.Duration(rand.Int63n(int64(span*2)+1))
}

func newStreamConn(t *tunnel, streamID uint32, ch chan *streamFrame, cmd byte) *streamConn {
	return &streamConn{
		t:        t,
		streamID: streamID,
		ch:       ch,
		cmd:      cmd,
		closed:   make(chan struct{}),
	}
}

// addr 是一个简单的 net.Addr 实现。
type addr struct{ network, str string }

func (a addr) Network() string { return a.network }
func (a addr) String() string  { return a.str }

// Read 从流中读取数据，去除 0x02 DATA 前缀。
// 使用内部 readBuf 防止调用者以小块读取时发生数据丢失
// （例如 crypto/tls 在读取记录体之前先读取 5 字节的 TLS 记录头部）。
func (c *streamConn) Read(p []byte) (int, error) {
	for {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		default:
		}

		c.readMu.Lock()
		if len(c.readBuf) > 0 {
			n := copy(p, c.readBuf)
			c.readBuf = c.readBuf[n:]
			if len(c.readBuf) == 0 {
				c.readBuf = nil
			}
			c.readMu.Unlock()
			return n, nil
		}
		c.readMu.Unlock()

		deadline, changed := c.readDeadlineState()
		timer, expired := deadlineTimer(deadline)
		if expired {
			return 0, &net.OpError{Op: "read", Net: "chimney", Err: &timeoutError{}}
		}

		select {
		case sf, ok := <-c.ch:
			stopTimer(timer)
			if !ok {
				return 0, io.EOF
			}
			if sf.fh.Type == h2engine.FrameData && len(sf.payload) > 0 {
				switch sf.payload[0] {
				case 0x02: // 带 chimney 前缀的 DATA
					data := sf.payload[1:]
					n := copy(p, data)
					if n < len(data) {
						c.readMu.Lock()
						c.readBuf = append(c.readBuf, data[n:]...)
						c.readMu.Unlock()
					}
					return n, nil
				case 0x03: // 关闭
					return 0, io.EOF
				default:
					// 无 chimney 前缀 — 分片写入的续段。
					// 整个载荷为原始数据。
					n := copy(p, sf.payload)
					if n < len(sf.payload) {
						c.readMu.Lock()
						c.readBuf = append(c.readBuf, sf.payload[n:]...)
						c.readMu.Unlock()
					}
					return n, nil
				}
			}
			return 0, nil
		case <-c.closed:
			stopTimer(timer)
			return 0, net.ErrClosed
		case <-c.t.quit:
			stopTimer(timer)
			return 0, io.ErrClosedPipe
		case <-timerC(timer):
			return 0, &net.OpError{Op: "read", Net: "chimney", Err: &timeoutError{}}
		case <-changed:
			stopTimer(timer)
			continue
		}
	}
}

// Write 将数据写入流，前缀添加 0x02 DATA 命令。
// 如果配置了流量配置文件，记录将被填充到目标大小。
func (c *streamConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}

	cmd := c.cmd
	if cmd == 0 {
		cmd = cmdTCP
	}

	targetSize := c.t.stealth.targetSize(c.t.prof)

	if cmd != cmdTCP {
		if err := c.writeCommandFrame(cmd, p, targetSize); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	for offset := 0; offset < len(p); {
		chunkSize := len(p) - offset
		if chunkSize > maxTunnelDataChunk {
			chunkSize = maxTunnelDataChunk
		}
		if err := c.writeCommandFrame(cmd, p[offset:offset+chunkSize], targetSize); err != nil {
			return offset, err
		}
		offset += chunkSize
	}
	return len(p), nil
}

func (c *streamConn) writeCommandFrame(cmd byte, payload []byte, targetSize uint16) error {
	if expired := c.prepareWriteDeadline(); expired {
		return &net.OpError{Op: "write", Net: "chimney", Err: &timeoutError{}}
	}

	needed := 1 + len(payload)

	// 对典型帧大小使用池；超大写入（大 UDP 数据报）直接分配。
	var data []byte
	var poolPtr *[]byte
	if needed <= writeBufSize {
		poolPtr = writeBufPool.Get().(*[]byte)
		data = (*poolPtr)[:needed]
	} else {
		data = make([]byte, needed)
	}
	if poolPtr != nil {
		defer writeBufPool.Put(poolPtr)
	}

	data[0] = cmd
	copy(data[1:], payload)

	return writeShapedData(c.t.h2Eng, c.streamID, data, targetSize, false)
}

func (c *streamConn) readDeadlineState() (time.Time, <-chan struct{}) {
	c.deadlineMu.Lock()
	if c.readDeadlineChanged == nil {
		c.readDeadlineChanged = make(chan struct{})
	}
	deadline := c.readDeadline
	changed := c.readDeadlineChanged
	c.deadlineMu.Unlock()
	return deadline, changed
}

func deadlineTimer(deadline time.Time) (*time.Timer, bool) {
	if deadline.IsZero() {
		return nil, false
	}
	d := time.Until(deadline)
	if d <= 0 {
		return nil, true
	}
	return time.NewTimer(d), false
}

func timerC(timer *time.Timer) <-chan time.Time {
	if timer == nil {
		return nil
	}
	return timer.C
}

func stopTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (c *streamConn) prepareWriteDeadline() bool {
	c.deadlineMu.Lock()
	deadline := c.writeDeadline
	c.deadlineMu.Unlock()

	if deadline.IsZero() {
		return false
	}
	if time.Until(deadline) <= 0 {
		return true
	}
	return false
}

// IsDead 在所有隧道的调度 goroutine 都已退出时返回 true，
// 表明底层连接已死，需要新的拨号器。
func (d *Dialer) IsDead() bool {
	for _, t := range d.pool {
		select {
		case <-t.dead:
		default:
			return false
		}
	}
	return true
}

// LastError 返回任何隧道的最后一次调度错误，如果没有则返回 nil。
// 用于诊断拨号器死亡的原因。
func (d *Dialer) LastError() error {
	for _, t := range d.pool {
		if err := t.LastError(); err != nil {
			return err
		}
	}
	return nil
}

// Close 发送 CLOSE 命令并取消注册流。
func (c *streamConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.onRelease != nil {
			c.onRelease()
		}
		if c.t != nil && c.t.h2Eng != nil {
			err = writeShapedData(c.t.h2Eng, c.streamID, []byte{cmdClose}, c.t.stealth.targetSize(c.t.prof), false)
		}
		if c.t != nil {
			c.t.mu.Lock()
			delete(c.t.streams, c.streamID)
			c.t.mu.Unlock()
		}
		c.readMu.Lock()
		c.readBuf = nil
		c.readMu.Unlock()
	})
	if err != nil {
		return err
	}

	// 排空缓冲帧，以便载荷可被立即 GC。
	// 此处不关闭通道 — 关闭会与 dispatchFrames 产生竞态，
	// 后者可能已经获取了通道引用。
	// 当此 streamConn 离开作用域时通道会被 GC，
	// 隧道关闭时任何剩余的缓冲帧由 closeTunnel 清理。
	for {
		select {
		case <-c.ch:
		default:
			return nil
		}
	}
}

func (c *streamConn) LocalAddr() net.Addr  { return addr{"chimney", "client"} }
func (c *streamConn) RemoteAddr() net.Addr { return addr{"chimney", "relay"} }

func (c *streamConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.signalReadDeadlineChangedLocked()
	c.deadlineMu.Unlock()
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	c.signalReadDeadlineChangedLocked()
	return nil
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *streamConn) signalReadDeadlineChangedLocked() {
	if c.readDeadlineChanged != nil {
		close(c.readDeadlineChanged)
	}
	c.readDeadlineChanged = make(chan struct{})
}

// ---------------------------------------------------------------------------
// UDP 支持 — 基于 Chimney H2 流的 net.PacketConn。
//
// 与其他流隧道协议（VLESS、Trojan、Shadowsocks）类似，一个 PacketConn
// 的所有 UDP 数据报通过单个 H2 流复用。H2 DATA 帧提供天然的报文边界，
// 因此无需长度前缀。
// ---------------------------------------------------------------------------

// 命令字节前缀到 H2 DATA 帧载荷，供中继区分 TCP 流和 UDP 流。
const (
	cmdTCP   = 0x02 // TCP 数据
	cmdClose = 0x03 // 流关闭
	cmdUDP   = 0x04 // UDP 数据报

	// maxTunnelDataChunk 为 Chimney 隧道命令前缀留出一个字节，
	// 以便每个 TCP H2 DATA 帧携带其自身的 cmdTCP 字节。
	maxTunnelDataChunk = 16*1024 - 1

	// writeBufSize 是写缓冲池每块的大小:1 字节命令前缀 + 最大 TCP 分片。
	// TCP 写路径的 needed = 1+len(payload) 永不超过它;更大的写入(如大 UDP
	// 数据报)回退到堆分配。此前池块为 64KB,在高并发上传下每条等待写锁的流
	// 都攥着一块,内存随并发线性膨胀(iOS NE OOM 主因)。
	writeBufSize = 1 + maxTunnelDataChunk
)

// UDP 数据报在 DATA 帧载荷中的线格式：
//
//	[1B cmd=0x04][1B addrType][addr][2B port][payload]
//
// addrType: 0x01 = IPv4 (4B), 0x03 = 域名 (1B 长度 + N 字节), 0x04 = IPv6 (16B)

// udpConn 在单个 Chimney H2 流上实现 net.PacketConn。
// 所有数据报共享一个流；H2 DATA 帧边界界定报文。
type udpConn struct {
	d      *Dialer
	t      *tunnel
	stream *streamConn

	mu                  sync.Mutex
	readDeadline        time.Time
	writeDeadline       time.Time
	readDeadlineChanged chan struct{}
	closed              bool
}

// 确保 udpConn 满足 net.PacketConn。
var _ net.PacketConn = (*udpConn)(nil)

// ReadFrom 读取一个 UDP 数据报，返回载荷和源地址。
func (u *udpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		u.mu.Lock()
		if u.closed {
			u.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		deadline := u.readDeadline
		u.mu.Unlock()

		timer, expired := deadlineTimer(deadline)
		if expired {
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: &timeoutError{}}
		}

		select {
		case sf, ok := <-u.stream.ch:
			stopTimer(timer)
			if !ok {
				return 0, nil, net.ErrClosed
			}
			payload := sf.payload
			if len(payload) < 1 || payload[0] != cmdUDP {
				continue
			}
			n, addr, err := parseDatagram(payload, b)
			if err != nil {
				continue
			}
			return n, addr, nil
		case <-timerC(timer):
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: &timeoutError{}}
		case <-u.stream.closed:
			stopTimer(timer)
			return 0, nil, net.ErrClosed
		case <-u.t.quit:
			stopTimer(timer)
			return 0, nil, io.ErrClosedPipe
		case <-u.readDeadlineChangedChan():
			stopTimer(timer)
			continue
		}
	}
}

// parseDatagram 从 DATA 帧载荷中提取 UDP 数据报。
func parseDatagram(payload []byte, b []byte) (int, net.Addr, error) {
	if len(payload) < 4 || payload[0] != cmdUDP {
		return 0, nil, fmt.Errorf("chimney: invalid UDP frame")
	}
	addrType := payload[1]
	var host string
	var data []byte
	switch addrType {
	case 0x01: // IPv4
		if len(payload) < 8 {
			return 0, nil, fmt.Errorf("chimney: truncated IPv4 UDP frame")
		}
		host = net.IP(payload[2:6]).String()
		port := int(payload[6])<<8 | int(payload[7])
		data = payload[8:]
		n := copy(b, data)
		return n, &net.UDPAddr{IP: net.ParseIP(host), Port: port}, nil
	case 0x03: // 域名
		if len(payload) < 5 {
			return 0, nil, fmt.Errorf("chimney: truncated domain UDP frame")
		}
		nameLen := int(payload[2])
		if len(payload) < 5+nameLen {
			return 0, nil, fmt.Errorf("chimney: truncated domain UDP frame")
		}
		host = string(payload[3 : 3+nameLen])
		addrEnd := 3 + nameLen
		port := int(payload[addrEnd])<<8 | int(payload[addrEnd+1])
		data = payload[addrEnd+2:]
		n := copy(b, data)
		return n, &net.UDPAddr{IP: net.ParseIP(host), Port: port}, nil
	case 0x04: // IPv6
		if len(payload) < 20 {
			return 0, nil, fmt.Errorf("chimney: truncated IPv6 UDP frame")
		}
		host = net.IP(payload[2:18]).String()
		port := int(payload[18])<<8 | int(payload[19])
		data = payload[20:]
		n := copy(b, data)
		return n, &net.UDPAddr{IP: net.ParseIP(host), Port: port}, nil
	default:
		return 0, nil, fmt.Errorf("chimney: unknown UDP addr type %d", addrType)
	}
}

// encodeDatagram 构建 UDP 数据报的线格式（不含命令字节；
// streamConn.Write 根据流类型前缀添加正确的 cmd）。
func encodeDatagram(addr net.Addr, b []byte) []byte {
	host, port, ok := udpAddrParts(addr)
	if !ok {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if len(host) == 0 || len(host) > 255 || port < 0 || port > 65535 {
			return nil
		}
		buf := make([]byte, 1+1+len(host)+2+len(b))
		buf[0] = 0x03
		buf[1] = byte(len(host))
		copy(buf[2:2+len(host)], host)
		portOffset := 2 + len(host)
		buf[portOffset] = byte(port >> 8)
		buf[portOffset+1] = byte(port)
		copy(buf[portOffset+2:], b)
		return buf
	}

	ip4 := ip.To4()
	if ip4 != nil {
		buf := make([]byte, 1+4+2+len(b))
		buf[0] = 0x01
		copy(buf[1:5], ip4)
		buf[5] = byte(port >> 8)
		buf[6] = byte(port)
		copy(buf[7:], b)
		return buf
	}
	ip6 := ip.To16()
	if ip6 != nil {
		buf := make([]byte, 1+16+2+len(b))
		buf[0] = 0x04
		copy(buf[1:17], ip6)
		buf[17] = byte(port >> 8)
		buf[18] = byte(port)
		copy(buf[19:], b)
		return buf
	}
	return nil
}

func udpAddrParts(addr net.Addr) (host string, port int, ok bool) {
	if udpAddr, isUDP := addr.(*net.UDPAddr); isUDP {
		if udpAddr.IP == nil {
			return "", 0, false
		}
		return udpAddr.IP.String(), udpAddr.Port, true
	}
	host, portString, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0, false
	}
	port64, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return "", 0, false
	}
	return host, int(port64), true
}

// WriteTo 向指定地址发送一个 UDP 数据报。
func (u *udpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return 0, net.ErrClosed
	}
	u.mu.Unlock()

	data := encodeDatagram(addr, b)
	if data == nil {
		return 0, fmt.Errorf("chimney: unsupported address type %T", addr)
	}

	_, err := u.stream.Write(data)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close 关闭 UDP 流。
func (u *udpConn) Close() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil
	}
	u.closed = true
	u.mu.Unlock()

	return u.stream.Close()
}

func (u *udpConn) LocalAddr() net.Addr  { return addr{"chimney-udp", "client"} }
func (u *udpConn) RemoteAddr() net.Addr { return addr{"chimney-udp", "relay"} }

func (u *udpConn) SetDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.readDeadline = t
	u.writeDeadline = t
	u.signalReadDeadlineChangedLocked()
	return nil
}

func (u *udpConn) SetReadDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.readDeadline = t
	u.signalReadDeadlineChangedLocked()
	return nil
}

func (u *udpConn) SetWriteDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.writeDeadline = t
	return nil
}

func (u *udpConn) readDeadlineChangedChan() <-chan struct{} {
	u.mu.Lock()
	if u.readDeadlineChanged == nil {
		u.readDeadlineChanged = make(chan struct{})
	}
	ch := u.readDeadlineChanged
	u.mu.Unlock()
	return ch
}

func (u *udpConn) signalReadDeadlineChangedLocked() {
	if u.readDeadlineChanged != nil {
		close(u.readDeadlineChanged)
		u.readDeadlineChanged = make(chan struct{})
	}
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// ListenPacket 通过 Chimney 隧道打开一个 UDP 数据包连接。
// 单个 H2 流承载所有 UDP 数据报；H2 DATA 帧边界提供天然的报文分隔。
func (d *Dialer) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	if len(d.pool) == 0 {
		d.mu.Unlock()
		return nil, fmt.Errorf("chimney: no tunnels available; call DialContext first")
	}
	poolLen := len(d.pool)
	d.mu.Unlock()

	ch := make(chan *streamFrame, d.streamChanBuf())
	start := int(d.next.Add(1) % uint32(poolLen))
	var t *tunnel
	var streamID uint32
	var lastErr error
	for attempt := 0; attempt < poolLen; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		idx := uint32((start + attempt) % poolLen)
		candidate, err := d.ensureTunnel(idx)
		if err != nil {
			lastErr = err
			continue
		}
		select {
		case <-candidate.dead:
			lastErr = net.ErrClosed
			continue
		default:
		}
		t = candidate
		streamID = t.h2Eng.OpenStream()
		break
	}
	if t == nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("chimney: no tunnels available")
	}

	t.mu.Lock()
	t.streams[streamID] = ch
	t.mu.Unlock()

	return &udpConn{
		d:      d,
		t:      t,
		stream: newStreamConn(t, streamID, ch, cmdUDP),
	}, nil
}

// newTunnel 建立到中继的单个 H2 隧道连接。
func newTunnel(config Config, prof *profile.Model, dil *dilution.Provider) (*tunnel, error) {
	// 步骤 1：TCP 连接。优先用宿主注入的 dialer(interface-aware,切网可重绑);
	// 否则回退到默认 net.DialTimeout。
	var rawConn net.Conn
	var err error
	if config.DialContext != nil {
		dctx, cancel := context.WithTimeout(context.Background(), config.ConnectTimeout)
		rawConn, err = config.DialContext(dctx, "tcp", config.RelayAddr)
		cancel()
	} else {
		rawConn, err = net.DialTimeout("tcp", config.RelayAddr, config.ConnectTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("chimney: connect to relay: %w", err)
	}

	tcpBufSize := config.TCPBufferSize
	if tcpBufSize <= 0 {
		tcpBufSize = 256 * 1024
	}
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetReadBuffer(tcpBufSize)
		tcpConn.SetWriteBuffer(tcpBufSize)
		tcpConn.SetNoDelay(true)
	}
	if err := rawConn.SetDeadline(time.Now().Add(config.HandshakeTimeout)); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("chimney: set handshake deadline: %w", err)
	}

	// 步骤 2：uTLS 握手
	tlsConfig := &utls.Config{
		ServerName:         config.SNI,
		InsecureSkipVerify: true,
		NextProtos:         defaultTLSNextProtos(),
	}

	var uConn *utls.UConn
	if config.ClientHelloFile != "" {
		// 精确校准:每条连接从原始字节重建独立 spec,HelloCustom + ApplyPreset
		// 复刻真实 ClientHello。SNI 由 config.ServerName(=config.SNI)填充,
		// 不会回放捕获时的 SNI。
		raw, lerr := loadClientHelloRaw(config.ClientHelloFile)
		if lerr != nil {
			rawConn.Close()
			return nil, lerr
		}
		spec, serr := buildClientHelloSpec(raw)
		if serr != nil {
			rawConn.Close()
			return nil, serr
		}
		uConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
		if aerr := uConn.ApplyPreset(spec); aerr != nil {
			rawConn.Close()
			return nil, fmt.Errorf("chimney: apply client hello spec: %w", aerr)
		}
	} else {
		// 从指纹规格中选取(列表/rotate 关键字时随机轮换),逐隧道分散 JA3。
		fpID, ferr := selectFingerprint(config.Fingerprint)
		if ferr != nil {
			rawConn.Close()
			return nil, fmt.Errorf("chimney: %w", ferr)
		}
		uConn = utls.UClient(rawConn, tlsConfig, fpID)
	}
	uConn.SetSNI(config.SNI)

	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("chimney: TLS handshake: %w", err)
	}
	if negotiated := uConn.ConnectionState().NegotiatedProtocol; negotiated != "h2" {
		uConn.Close()
		return nil, fmt.Errorf("chimney: TLS ALPN negotiated %q, want h2", negotiated)
	}

	serverRandom := uConn.HandshakeState.ServerHello.Random
	clientRandom := uConn.HandshakeState.Hello.Random

	if len(serverRandom) != 32 || len(clientRandom) != 32 {
		uConn.Close()
		return nil, fmt.Errorf("chimney: invalid random length")
	}

	// 步骤 3：密钥派生
	deriver, err := keyderiv.NewDeriverFromHex(config.PSK)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: create deriver: %w", err)
	}

	tag, err := deriver.AuthTag(serverRandom, clientRandom, config.TagLen)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: auth tag: %w", err)
	}

	userID := config.UserID
	if userID == "" {
		userID = "default"
	}
	keyHint := keyderiv.ComputeKeyHint(userID)

	sendKey, recvKey, err := deriver.DeriveDirectionalKeys(serverRandom, clientRandom)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: directional keys: %w", err)
	}

	sendNonceBase, err := deriver.DeriveNonceBase(serverRandom, clientRandom)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: send nonce: %w", err)
	}

	recvNonceBase, err := deriver.DeriveNonceBase(clientRandom, serverRandom)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: recv nonce: %w", err)
	}

	codec, err := record.NewCodecWithDirectionalKeys(sendKey, sendNonceBase, recvKey, recvNonceBase)
	if err != nil {
		kSess, _ := deriver.DeriveSessionKey(serverRandom, clientRandom)
		nonceBase, _ := deriver.DeriveNonceBase(serverRandom, clientRandom)
		codec, err = record.NewCodec(kSess, nonceBase)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("chimney: create codec: %w", err)
		}
	}

	// 步骤 4：提取原始 TCP 连接用于记录层。
	// 交换后，Chimney 记录编解码器直接在 TCP 流上操作 —
	// TLS 不再参与其中。
	rawTCPConn := uConn.GetUnderlyingConn()

	// 步骤 5：记录层
	recReader := record.NewRecordReader(rawTCPConn, codec)
	recWriter := record.NewRecordWriter(rawTCPConn, codec)

	// 步骤 6：发送 H2 前言 + SETTINGS
	settings := h2engine.DefaultSettings()
	h2Opening := h2engine.GenerateClientOpeningSequence(settings)
	if err := recWriter.WriteRecord(h2Opening); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: send H2 preface: %w", err)
	}

	// 步骤 7：创建 H2 引擎
	h2Eng := h2engine.NewEngine(settings, codec)
	h2Eng.SetRecordIO(recReader, recWriter)

	// 步骤 8：完成 H2 握手
	fh, _, err := h2Eng.ReadFrame()
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: read server SETTINGS: %w", err)
	}
	if fh.Type != h2engine.FrameSettings {
		uConn.Close()
		return nil, fmt.Errorf("chimney: expected SETTINGS, got type 0x%x", fh.Type)
	}

	ackFrame := h2engine.DefaultSettings().EncodeSettings(true)
	if err := recWriter.WriteRecord(ackFrame); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: send SETTINGS ACK: %w", err)
	}

	fh, _, err = h2Eng.ReadFrame()
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: read SETTINGS ACK: %w", err)
	}
	if fh.Type != h2engine.FrameSettings || fh.Flags&h2engine.FlagAck == 0 {
		uConn.Close()
		return nil, fmt.Errorf("chimney: expected SETTINGS ACK, got type 0x%x flags 0x%x", fh.Type, fh.Flags)
	}

	// 步骤 9：发送认证标签
	authStreamID := h2Eng.OpenStream()
	authPayload := make([]byte, 4+len(tag))
	copy(authPayload, keyHint[:])
	copy(authPayload[4:], tag)
	tagFrame := h2engine.DataFrame(authStreamID, 0, authPayload)
	if err := recWriter.WriteRecord(tagFrame); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: send auth tag: %w", err)
	}
	if err := rawTCPConn.SetDeadline(time.Time{}); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: clear handshake deadline: %w", err)
	}

	chanBuf := config.StreamChannelBuffer
	if chanBuf <= 0 {
		chanBuf = DefaultStreamChannelBuffer
	}
	t := &tunnel{
		rawConn:   rawTCPConn,
		h2Eng:     h2Eng,
		recReader: recReader,
		recWriter: recWriter,
		prof:      prof,
		padTarget: config.PaddingTarget,
		stealth:   newTrafficShaper(config),
		dilution:  dil,
		chanBuf:   chanBuf,
		bornAt:    time.Now(),
		streams:   make(map[uint32]chan *streamFrame),
		quit:      make(chan struct{}),
		dead:      make(chan struct{}),
		pong:      make(chan struct{}, 1),
	}
	t.lastRecv.Store(time.Now().UnixNano())
	if config.MaxTunnelLifetime > 0 {
		t.expiresAt = t.bornAt.Add(jitterTunnelLifetime(config.MaxTunnelLifetime))
	}

	go t.dispatchFrames()
	if dil != nil && prof != nil {
		go t.dilutionLoop()
	}

	return t, nil
}

// NewDialer 连接到 Chimney 中继，建立 PoolSize 个 TLS+H2 隧道，
// 并返回一个可通过 DialContext 打开流的 Dialer。
func NewDialer(config Config) (*Dialer, error) {
	if err := config.Normalize(); err != nil {
		return nil, err
	}

	var prof *profile.Model
	if config.ProfilePath != "" {
		var err error
		prof, err = profile.LoadModelFromFile(config.ProfilePath)
		if err != nil {
			return nil, fmt.Errorf("chimney: load profile: %w", err)
		}
	}

	var dil *dilution.Provider
	if config.DilutionPath != "" {
		var err error
		dil, err = dilution.LoadProviderFromFile(config.DilutionPath)
		if err != nil {
			return nil, fmt.Errorf("chimney: load dilution: %w", err)
		}
	}

	pool := make([]*tunnel, config.PoolSize)
	for i := 0; i < config.PoolSize; i++ {
		t, err := newTunnel(config, prof, dil)
		if err != nil {
			// 部分失败时关闭已创建的隧道。
			for j := 0; j < i; j++ {
				pool[j].closeTunnel()
			}
			return nil, err
		}
		pool[i] = t
	}

	d := &Dialer{
		config:   config,
		pool:     pool,
		prof:     prof,
		dilution: dil,
		dialNew:  newTunnel,
	}
	if config.MaxConcurrentStreams > 0 {
		d.streamSem = make(chan struct{}, config.MaxConcurrentStreams)
	}
	d.healthStop = make(chan struct{})
	go d.healthLoop()
	return d, nil
}

// ensureTunnel 返回 pool[idx] 处的隧道，如果现有隧道的调度 goroutine
// 已退出则替换为新隧道。每次只有一个 goroutine 替换指定槽位；
// 并发调用者阻塞在 d.mu 上，然后复用刚创建的隧道。
func (d *Dialer) ensureTunnel(idx uint32) (*tunnel, error) {
	t := d.pool[idx]
	select {
	case <-t.dead:
	// 隧道已死 — 尝试替换。
	default:
		if !t.shouldRotate() {
			return t, nil // 仍然存活
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil, net.ErrClosed
	}

	// 在锁下重新检查：另一个 goroutine 可能已经替换了它。
	if d.pool[idx].shouldRotate() {
		d.pool[idx].closeTunnel()
	}
	select {
	case <-d.pool[idx].dead:
	default:
		return d.pool[idx], nil
	}

	dialNew := d.dialNew
	if dialNew == nil {
		dialNew = newTunnel
	}
	newT, err := dialNew(d.config, d.prof, d.dilution)
	if err != nil {
		return nil, fmt.Errorf("chimney: reconnect failed: %w", err)
	}
	d.pool[idx].closeTunnel()
	d.pool[idx] = newT
	return newT, nil
}

func (t *tunnel) shouldRotate() bool {
	if t == nil || t.expiresAt.IsZero() || time.Now().Before(t.expiresAt) {
		return false
	}
	t.mu.Lock()
	active := len(t.streams)
	t.mu.Unlock()
	return active == 0
}

// DialContext 通过 Chimney 隧道打开一个新的 H2 流到目标地址。
// 返回的 net.Conn 是一个通过 H2 复用的虚拟连接。
// 流在连接池中轮询分配。
//
// network 参数被忽略（始终为 TCP）。addr 必须是 "host:port" 格式。
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	poolLen := len(d.pool)
	d.mu.Unlock()

	if poolLen == 0 {
		return nil, fmt.Errorf("chimney: no tunnels available")
	}

	// 并发流上限:超限时阻塞等待空位(或 ctx 取消),硬性封顶内存。
	if d.streamSem != nil {
		select {
		case d.streamSem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	conn, err := d.dialPooled(ctx, addr)
	if err != nil {
		d.releaseStreamSlot()
		return nil, err
	}
	// 成功:把配额释放绑定到该流的 Close。
	if d.streamSem != nil {
		if sc, ok := conn.(*streamConn); ok {
			sc.onRelease = d.releaseStreamSlot
		} else {
			d.releaseStreamSlot() // 未知连接类型无法追踪,立即释放避免泄漏
		}
	}
	return conn, nil
}

// releaseStreamSlot 释放一个并发流配额(若启用了上限)。
func (d *Dialer) releaseStreamSlot() {
	if d.streamSem != nil {
		select {
		case <-d.streamSem:
		default:
		}
	}
}

// dialPooled 在连接池中轮询分配,自动重连已死的隧道。
// 如果一个槽位无法重连,尝试剩余槽位后再将错误返回给调用者（如 sing-box）。
func (d *Dialer) dialPooled(ctx context.Context, addr string) (net.Conn, error) {
	d.mu.Lock()
	poolLen := len(d.pool)
	d.mu.Unlock()

	start := int(d.next.Add(1) % uint32(poolLen))
	var lastErr error
	for attempt := 0; attempt < poolLen; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		idx := uint32((start + attempt) % poolLen)
		t, err := d.ensureTunnel(idx)
		if err != nil {
			lastErr = err
			continue
		}
		conn, err := t.dialContext(ctx, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !isTunnelUnavailable(err) {
			return nil, err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("chimney: no tunnels available")
}

func isTunnelUnavailable(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

// dialContext 在单个隧道上打开一个流。
func (t *tunnel) dialContext(ctx context.Context, addr string) (net.Conn, error) {
	select {
	case <-t.dead:
		if err := t.LastError(); err != nil {
			return nil, fmt.Errorf("chimney: tunnel closed: %w", err)
		}
		return nil, net.ErrClosed
	default:
	}

	streamID := t.h2Eng.OpenStream()
	ch := make(chan *streamFrame, t.chanBuf)

	t.mu.Lock()
	t.streams[streamID] = ch
	t.mu.Unlock()

	connectCmd := make([]byte, 1+len(addr))
	connectCmd[0] = 0x01
	copy(connectCmd[1:], addr)
	if err := writeShapedData(t.h2Eng, streamID, connectCmd, t.stealth.targetSize(t.prof), false); err != nil {
		t.mu.Lock()
		delete(t.streams, streamID)
		t.mu.Unlock()
		select {
		case <-t.dead:
			if lastErr := t.LastError(); lastErr != nil {
				return nil, fmt.Errorf("chimney: tunnel closed: %w", lastErr)
			}
			return nil, net.ErrClosed
		default:
		}
		return nil, fmt.Errorf("chimney: CONNECT: %w", err)
	}

	// CONNECT_OK 应用层超时:假死隧道(底层 TCP 尚未报错,如 iOS 切网后旧连接
	// 黑洞)不会回 CONNECT_OK。超时即主动判定该隧道不可用并触发重建,使新连接
	// 在 ~connectAckTimeout 内绕开它,而非干等到 TCP 重传超时(~9-15s)。
	ackTimer := time.NewTimer(connectAckTimeout)
	defer ackTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			t.mu.Lock()
			delete(t.streams, streamID)
			t.mu.Unlock()
			return nil, ctx.Err()
		case <-t.quit:
			t.mu.Lock()
			delete(t.streams, streamID)
			t.mu.Unlock()
			return nil, net.ErrClosed
		case <-ackTimer.C:
			t.mu.Lock()
			delete(t.streams, streamID)
			t.mu.Unlock()
			go t.closeTunnel()           // 主动拆除假死隧道 → health-loop/ensureTunnel 重建
			return nil, io.ErrClosedPipe // isTunnelUnavailable → 上层换下一条隧道
		case sf, ok := <-ch:
			if !ok {
				return nil, net.ErrClosed
			}
			if sf.fh.Type == h2engine.FrameData && len(sf.payload) > 0 {
				switch sf.payload[0] {
				case 0x01:
					return newStreamConn(t, streamID, ch, cmdTCP), nil
				default:
					t.mu.Lock()
					delete(t.streams, streamID)
					t.mu.Unlock()
					return nil, fmt.Errorf("chimney: backend connect failed: code 0x%02x", sf.payload[0])
				}
			}
		}
	}
}

// Close 关闭连接池中的所有隧道。
func (d *Dialer) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.mu.Unlock()

	if d.healthStop != nil {
		close(d.healthStop)
	}
	for _, t := range d.pool {
		t.closeTunnel()
	}
	return nil
}

func (t *tunnel) closeTunnel() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	close(t.quit)
	t.mu.Unlock()

	if t.recWriter != nil {
		t.recWriter.Close()
	}
	var err error
	if t.rawConn != nil {
		err = t.rawConn.Close()
	}
	<-t.dead
	return err
}

// dispatchFrames 从 H2 引擎读取帧并将其路由到每个流的通道。
// tunnelIdleTimeout 是在未收到任何帧的情况下，隧道被认为已死并拆除前的最大持续时间。
// 这防止 dispatchFrames 在卡住的 Windows TCP 回环连接上永远阻塞。
const tunnelIdleTimeout = 30 * time.Second

// connectAckTimeout 是等待中继 CONNECT_OK 的应用层超时(安全网)。
// 必须 > 中继拨后端的超时(~10s),否则"慢后端"(目标站点连接慢)会被误判为
// 隧道假死、导致慢站点连不上。真正快速发现假死靠后台 PING 探活(pingIfIdle),
// 它独立于后端速度,~pingIdleThreshold+pingTimeout 内拆除假死隧道。
const connectAckTimeout = 12 * time.Second

func (t *tunnel) dispatchFrames() {
	defer close(t.dead)

	// 滚动读取截止时间：每次成功 ReadFrame 后延长，
	// 使活动隧道永不过期；卡住的连接在 tunnelIdleTimeout 秒内被检测到。
	t.rawConn.SetReadDeadline(time.Now().Add(tunnelIdleTimeout))

	for {
		select {
		case <-t.quit:
			t.mu.Lock()
			for _, ch := range t.streams {
				close(ch)
			}
			t.streams = make(map[uint32]chan *streamFrame)
			t.mu.Unlock()
			return
		default:
		}
		fh, payload, err := t.h2Eng.ReadFrame()
		if err != nil {
			sealerSeq, openerSeq := t.h2Eng.CodecSeqs()
			sealerTrail, openerTrail := t.h2Eng.CodecTrails()
			lastErr := fmt.Errorf("frame read: %w [sealer_seq=%d opener_seq=%d]\nsealer trail (last 32):\n%s\nopener trail (last 32):\n%s",
				err, sealerSeq, openerSeq, sealerTrail, openerTrail)
			t.mu.Lock()
			t.lastError = lastErr
			for _, ch := range t.streams {
				close(ch)
			}
			t.streams = make(map[uint32]chan *streamFrame)
			t.mu.Unlock()
			return
		}
		// 每次成功接收帧后延长截止时间并记录活动时间。
		t.rawConn.SetReadDeadline(time.Now().Add(tunnelIdleTimeout))
		t.lastRecv.Store(time.Now().UnixNano())

		// PONG(PING+ACK)是连接级帧(stream 0),不路由到流,唤醒 ping()。
		if fh.Type == h2engine.FramePing {
			if fh.Flags&h2engine.FlagAck != 0 {
				select {
				case t.pong <- struct{}{}:
				default:
				}
			}
			continue
		}

		t.mu.Lock()
		ch, ok := t.streams[fh.StreamID]
		t.mu.Unlock()
		if ok {
			// 快速路径：通道有空间 — 无需分配定时器。
			select {
			case ch <- &streamFrame{fh, payload}:
			default:
				// 慢速路径：通道已满。带超时等待 — 消费者
				// 在 tunnelIdleTimeout 内卡住会导致 TCP 接收缓冲区饥饿
				// 并使隧道死锁，因此必要时拆除它。
				select {
				case ch <- &streamFrame{fh, payload}:
				case <-t.quit:
				case <-time.After(tunnelIdleTimeout):
					t.rawConn.Close()
					t.mu.Lock()
					for _, c := range t.streams {
						close(c)
					}
					t.streams = make(map[uint32]chan *streamFrame)
					t.mu.Unlock()
					return
				}
			}
		}
	}
}

// dilutionLoop 定期发送带有真实 HTTP 内容的稀释记录。
func (t *tunnel) dilutionLoop() {
	interval := t.prof.RecordDelay()
	if interval <= 0 {
		interval = 2 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.quit:
			return
		case <-ticker.C:
			targetSize := t.prof.RecordSize()
			content := t.dilution.GetBlock(targetSize)
			if content == nil {
				continue
			}
			if err := t.h2Eng.WriteDilutionRecord(content, targetSize); err != nil {
				return
			}
			nextInterval := t.prof.RecordDelay()
			if nextInterval > 0 {
				ticker.Reset(nextInterval)
			}
		}
	}
}

// fingerprintRotatePool 是关键字 "rotate"/"auto" 展开的默认真实浏览器指纹池。
// 通用方案:不依赖站点抓包,通过在多个真实浏览器指纹间轮换,使 JA3 从单一
// 固定值变为跨浏览器的分布,瓦解基于固定 JA3 / 扩展数量的分类器。
var fingerprintRotatePool = []string{"chrome", "firefox", "edge", "safari", "ios"}

// expandFingerprintSpec 把指纹规格串解析为名称列表。
// 支持:单个名称、逗号分隔列表,以及关键字 "rotate"/"auto"(展开为默认池)。
// 空串回退到 "chrome"。
func expandFingerprintSpec(spec string) []string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return []string{"chrome"}
	}
	switch strings.ToLower(spec) {
	case "rotate", "auto":
		pool := make([]string, len(fingerprintRotatePool))
		copy(pool, fingerprintRotatePool)
		return pool
	}
	parts := strings.Split(spec, ",")
	names := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			names = append(names, p)
		}
	}
	if len(names) == 0 {
		return []string{"chrome"}
	}
	return names
}

// validateFingerprintSpec 校验规格串中每个指纹名都有效。
func validateFingerprintSpec(spec string) error {
	for _, name := range expandFingerprintSpec(spec) {
		if _, err := parseFingerprint(name); err != nil {
			return err
		}
	}
	return nil
}

// selectFingerprint 从规格串中选取一个指纹 ClientHelloID。
// 列表含多项时随机挑选——每次新建隧道独立调用,从而在连接维度上轮换 JA3。
func selectFingerprint(spec string) (utls.ClientHelloID, error) {
	names := expandFingerprintSpec(spec)
	name := names[0]
	if len(names) > 1 {
		name = names[rand.Intn(len(names))]
	}
	return parseFingerprint(name)
}

// parseFingerprint 将名称字符串映射到 uTLS ClientHelloID。
func parseFingerprint(name string) (utls.ClientHelloID, error) {
	normalized := strings.ToLower(name)

	switch normalized {
	// Chrome
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "chrome-58":
		return utls.HelloChrome_58, nil
	case "chrome-62":
		return utls.HelloChrome_62, nil
	case "chrome-70":
		return utls.HelloChrome_70, nil
	case "chrome-72":
		return utls.HelloChrome_72, nil
	case "chrome-83":
		return utls.HelloChrome_83, nil
	case "chrome-87":
		return utls.HelloChrome_87, nil
	case "chrome-96":
		return utls.HelloChrome_96, nil
	case "chrome-100":
		return utls.HelloChrome_100, nil
	case "chrome-102":
		return utls.HelloChrome_102, nil
	case "chrome-106":
		return utls.HelloChrome_106_Shuffle, nil
	case "chrome-120":
		return utls.HelloChrome_120, nil
	case "chrome-120-pq":
		return utls.HelloChrome_120_PQ, nil

	// Firefox
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "firefox-55":
		return utls.HelloFirefox_55, nil
	case "firefox-56":
		return utls.HelloFirefox_56, nil
	case "firefox-63":
		return utls.HelloFirefox_63, nil
	case "firefox-65":
		return utls.HelloFirefox_65, nil
	case "firefox-99":
		return utls.HelloFirefox_99, nil
	case "firefox-102":
		return utls.HelloFirefox_102, nil
	case "firefox-105":
		return utls.HelloFirefox_105, nil
	case "firefox-120":
		return utls.HelloFirefox_120, nil

	// Safari
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "safari-16":
		return utls.HelloSafari_16_0, nil

	// iOS
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "ios-11":
		return utls.HelloIOS_11_1, nil
	case "ios-12":
		return utls.HelloIOS_12_1, nil
	case "ios-13":
		return utls.HelloIOS_13, nil
	case "ios-14":
		return utls.HelloIOS_14, nil

	// Edge
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "edge-85":
		return utls.HelloEdge_85, nil
	case "edge-106":
		return utls.HelloEdge_106, nil

	// Android
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil

	// 中国浏览器
	case "360":
		return utls.Hello360_Auto, nil
	case "360-7":
		return utls.Hello360_7_5, nil
	case "360-11":
		return utls.Hello360_11_0, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "qq-11":
		return utls.HelloQQ_11_1, nil

	// Randomized
	case "randomized":
		return utls.HelloRandomized, nil
	case "randomized-alpn":
		return utls.HelloRandomizedALPN, nil
	case "randomized-noalpn":
		return utls.HelloRandomizedNoALPN, nil

	// Golang
	case "golang":
		return utls.HelloGolang, nil

	default:
		return utls.ClientHelloID{},
			fmt.Errorf("unknown fingerprint %q (available: chrome, firefox, safari, ios, edge, android, 360, qq, randomized, golang)", name)
	}
}

func defaultTLSNextProtos() []string {
	return []string{"h2", "http/1.1"}
}

// 确保 streamConn 在编译时满足 net.Conn。
var _ net.Conn = (*streamConn)(nil)

// 确保 crypto/tls 可导入（utls.Config 遮蔽了它，但从未直接使用）。
var _ = tls.VersionTLS12

// RelayConfig 保存 Chimney 中继服务器的配置。
// 这是从外部包创建中继服务器的公共 API。
type RelayConfig struct {
	// ListenAddr 是监听的地址（例如 ":443"）。
	ListenAddr string

	// PSK 是单用户模式的预共享密钥（十六进制编码）。
	PSK string

	// Users 将用户标识符映射到其十六进制编码的 PSK，用于多用户模式。
	Users map[string]string

	// UserIDs 是多用户模式的用户标识符列表。
	// 每个用户的 PSK 通过 PSK = SHA256(userID) 派生。
	UserIDs []string

	// TagLen 是认证标签长度（字节）。
	TagLen int

	// IntentFile 是意图白名单文件的路径。
	// 如果 IntentYAML 非空则忽略。
	IntentFile string

	// EnforceFile 是强制 CIDR 文件的路径。
	// 如果 EnforceYAML 非空则忽略。
	EnforceFile string

	// IntentYAML 是内联的意图白名单 YAML 内容。
	// 非空时优先于 IntentFile。
	IntentYAML string

	// EnforceYAML 是内联的强制 CIDR YAML 内容。
	// 非空时优先于 EnforceFile。
	EnforceYAML string

	// CloudRegion 是用于 CIDR 验证的云区域。
	CloudRegion string

	// DefaultBackend 是未认证流量的后备后端。
	DefaultBackend string

	// HandshakeTimeout TLS 握手超时时间。
	HandshakeTimeout time.Duration

	// AuthReadTimeout 读取认证记录的超时时间。
	AuthReadTimeout time.Duration

	// EnableProfiling 启用流量分析和速率控制。
	EnableProfiling bool

	// ProfileDir 是包含站点配置文件的目录。
	ProfileDir string

	// BackendDialer 是可选的用于后端连接的自定义拨号器。
	BackendDialer func(ctx context.Context, network, addr string) (net.Conn, error)

	// StealthMode 启用下行流量塑形(记录 padding + 下行注水),使代理流量在
	// 记录大小、上下行字节比和满 MTU 占比上贴近真实 HTTPS 下载。
	StealthMode bool

	// DownlinkLevel 是下行注水等级:off/low/medium/high/max。
	// 空值在 StealthMode 下取 medium;off 仅做记录 padding、不注水。
	DownlinkLevel string

	// DownlinkRecordSize 是下行记录 padding 的固定目标大小(字节)。
	// 0 表示按流量 profile 采样(推荐)。
	DownlinkRecordSize int

	// DownlinkRatioTarget 显式覆盖等级的下行/上行字节比;负值关闭注水。
	DownlinkRatioTarget float64
}

// RelayServer 封装中继服务器供公共使用。
type RelayServer struct {
	srv *relay.Server
}

// NewRelayServer 创建一个新的 Chimney 中继服务器。
// 服务器在调用 Start() 之前不会开始监听。
func NewRelayServer(config *RelayConfig, logger *slog.Logger) (*RelayServer, error) {
	cfg := &relay.Config{
		ListenAddr:       config.ListenAddr,
		PSK:              config.PSK,
		Users:            config.Users,
		UserIDs:          config.UserIDs,
		TagLen:           config.TagLen,
		IntentFile:       config.IntentFile,
		EnforceFile:      config.EnforceFile,
		IntentYAML:       config.IntentYAML,
		EnforceYAML:      config.EnforceYAML,
		CloudRegion:      config.CloudRegion,
		DefaultBackend:   config.DefaultBackend,
		HandshakeTimeout: config.HandshakeTimeout,
		AuthReadTimeout:  config.AuthReadTimeout,
		EnableProfiling:  config.EnableProfiling,
		ProfileDir:       config.ProfileDir,
		BackendDialer:    config.BackendDialer,

		StealthMode:         config.StealthMode,
		DownlinkLevel:       config.DownlinkLevel,
		DownlinkRecordSize:  config.DownlinkRecordSize,
		DownlinkRatioTarget: config.DownlinkRatioTarget,
	}
	srv, err := relay.NewServer(cfg, logger)
	if err != nil {
		return nil, err
	}
	return &RelayServer{srv: srv}, nil
}

// Start 启动中继服务器监听器。
func (rs *RelayServer) Start() error {
	return rs.srv.Start()
}

// Stop 停止中继服务器并等待活动连接排空。
func (rs *RelayServer) Stop() error {
	return rs.srv.Stop()
}

// Stats 返回中继服务器统计信息。
func (rs *RelayServer) Stats() *relay.Stats {
	return rs.srv.Stats()
}
