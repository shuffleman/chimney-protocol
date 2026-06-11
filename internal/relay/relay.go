// Package relay 实现核心中继逻辑：TCP 转发、握手中继、
// 认证验证、调包以及隧道建立（第二部分 §6-§12）。
//
// 中继是 Chimney 的核心组件。对于每个客户端连接：
//
//  1. 读取 ClientHello，提取 SNI
//  2. 检查白名单（关卡A: SNI 意图，关卡B: 目标 IP）
//  3. 若任一项检查失败 → 被动回退（转发到默认后端
//     或自然关闭，与真实站点无异）
//  4. 将 TLS 握手转发到真实站点（纯 TCP 中继，不解密）
//  5. 观察 ServerHello，提取 ServerRandom
//  6. 握手后，从客户端读取第一个 application_data 记录
//  7. 计算预期的认证标签，与嵌入标签比较
//  8. 若标签匹配 → 调包：切断真实站点，用 K_sess 接管
//  9. 若标签不匹配 → 继续转发到真实站点（零区分度）
//
// 10. Chimney 模式下：H2 组帧、隧道化、流量画像调速
package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/auth"
	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/keyderiv"
	"github.com/shuffleman/chimney-protocol/internal/profile"
	"github.com/shuffleman/chimney-protocol/internal/record"
	"github.com/shuffleman/chimney-protocol/internal/whitelist"
)

const (
	// DefaultListenAddr 是中继的默认监听地址。
	DefaultListenAddr = ":443"

	// HandshakeTimeout 是 TLS 握手中继允许的最长时间。
	HandshakeTimeout = 10 * time.Second

	// AuthReadTimeout 是读取包含认证标签的第一个 application_data 记录的超时时间。
	AuthReadTimeout = 5 * time.Second

	// TCPBufferSize 是 TCP 中继的缓冲区大小。
	TCPBufferSize = 64 * 1024

	// MaxConcurrentBackendDials 限制并发的后端 TCP 拨号数量，
	// 以防止压垮后端的监听积压队列（TCP SYN 泛洪）。
	MaxConcurrentBackendDials = 64
)

var (
	// ErrHandshakeTimeout 在 TLS 握手耗时过长时返回。
	ErrHandshakeTimeout = errors.New("relay: TLS handshake timeout")

	// ErrAuthFailed 在认证标签验证失败时返回。
	// 这不是一个可区分的错误——调用者应继续转发到真实站点。
	ErrAuthFailed = errors.New("relay: authentication failed")

	// ErrSwapFailed 在调包操作失败时返回。
	ErrSwapFailed = errors.New("relay: swap failed")

	// ErrWhitelistFailed 在白名单检查失败时返回。
	// 这会触发被动回退。
	ErrWhitelistFailed = errors.New("relay: whitelist check failed")

	errStreamCanceled = errors.New("relay: stream canceled")
)

// Server 是 Chimney 中继服务器。
type Server struct {
	// 配置
	config *Config

	// 组件
	whitelistMgr *whitelist.Manager
	userStore    *auth.UserStore

	// 统计
	stats *Stats

	// 日志器
	logger *slog.Logger

	// 监听器
	listener net.Listener

	// 活动连接
	wg     sync.WaitGroup
	closed atomic.Bool

	// dialSem 限制所有隧道中并发的后端 TCP 拨号数量，
	// 以防止压垮后端的监听积压队列。
	dialSem chan struct{}

	// connSem 限制所有隧道中打开的后端连接总数。
	connSem chan struct{}

	// connectACL 限制经过认证的 CONNECT 目标地址。
	connectACL *connectACL
}

// Config 保存中继服务器的配置。
type Config struct {
	// ListenAddr 是监听的地址。
	ListenAddr string

	// PSK 是预共享密钥（十六进制编码）。仅用于单用户模式。
	// 若 Users 非空，则忽略 PSK。
	PSK string

	// Users 将用户标识符（如 UUID）映射到其十六进制编码的 PSK。
	// 设置后，启用带密钥提示查找的多用户认证。
	Users map[string]string

	// UserIDs 是多用户模式下的用户标识符列表（如 UUID）。
	// 每个用户的 PSK 通过 PSK = SHA256(userID) 推导。
	// 这是推荐字段——无需分别指定 PSK 值。
	// 若同时设置了 Users 和 UserIDs，Users 优先。
	UserIDs []string

	// TagLen 是认证标签的长度。
	TagLen int

	// IntentFile 是意图白名单文件的路径。
	// 若 IntentYAML 非空则忽略。
	IntentFile string

	// EnforceFile 是强制 CIDR 文件的路径。
	// 若 EnforceYAML 非空则忽略。
	EnforceFile string

	// IntentYAML 是内联的意图白名单 YAML 内容。
	// 非空时优先于 IntentFile。
	IntentYAML string

	// EnforceYAML 是内联的强制 CIDR YAML 内容。
	// 非空时优先于 EnforceFile。
	EnforceYAML string

	// CloudRegion 是用于 CIDR 验证的云区域（如 "us-east-1"）。
	CloudRegion string

	// DefaultBackend 是未经认证流量的回退后端。
	// 若为空，在白名单/认证失败时自然关闭连接。
	DefaultBackend string

	// HandshakeTimeout 是 TLS 握手中继的超时时间。
	HandshakeTimeout time.Duration

	// AuthReadTimeout 是读取认证记录的超时时间。
	AuthReadTimeout time.Duration

	// EnableProfiling 启用流量画像和速率调节。
	EnableProfiling bool

	// ProfileDir 是包含站点画像文件的目录。
	ProfileDir string

	// BackendDialer 是可选的用于后端连接的自定义拨号器。
	// 设置后，将代替 net.DialTimeout 用于隧道处理期间
	// 创建的所有后端连接（CONNECT 命令）。
	// 这允许与外部路由框架集成。
	// 签名与 net.Dialer.DialContext 匹配。
	BackendDialer func(ctx context.Context, network, addr string) (net.Conn, error)

	// ConnectAllowCIDRs 将经过认证的 CONNECT 目标限制为这些 CIDR 范围。
	// 空表示无允许列表限制。
	ConnectAllowCIDRs []string

	// ConnectDenyCIDRs 拒绝这些 CIDR 范围内的经过认证的 CONNECT 目标。
	// 拒绝规则优先于允许规则。
	ConnectDenyCIDRs []string

	// ConnectDenyPrivate 拒绝认证后的私有、回环、链路本地、多播和
	// 未指定的 CONNECT 目标。
	ConnectDenyPrivate bool

	// StealthMode 启用下行流量塑形:对 relay→client 方向做记录 padding
	// 并按需注入下行填充,使代理流量在记录大小、上下行字节比和满 MTU
	// 占比上贴近真实 HTTPS 下载行为。关闭时下行按原始大小裸写。
	StealthMode bool

	// DownlinkLevel 是下行注水等级:off/low/medium/high/max。
	// 等级越高,目标 down:up 比越大、注入越密,伪装越强但下行带宽开销越大。
	// 空值在 StealthMode 下取 medium。off 仅做逐记录 padding、不注水。
	DownlinkLevel string

	// DownlinkRecordSize 是下行记录 padding 的固定目标明文大小(字节)。
	// 0 表示按流量 profile 采样,产生更真实的尺寸分布(推荐)。
	DownlinkRecordSize int

	// DownlinkRatioTarget 显式覆盖注水等级的目标下行/上行字节比(down:up)。
	// 0 表示采用 DownlinkLevel 的预设比值;负值关闭注水,仅做逐记录 padding。
	DownlinkRatioTarget float64
}

// DefaultConfig 返回默认配置。
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:       DefaultListenAddr,
		TagLen:           auth.DefaultTagLen,
		IntentFile:       whitelist.DefaultIntentFile,
		EnforceFile:      whitelist.DefaultEnforceFile,
		HandshakeTimeout: HandshakeTimeout,
		AuthReadTimeout:  AuthReadTimeout,
		EnableProfiling:  true,
	}
}

// Stats 保存中继统计信息。
type Stats struct {
	TotalConnections    atomic.Uint64
	ActiveConnections   atomic.Int64
	AuthenticatedSwaps  atomic.Uint64
	AuthFailures        atomic.Uint64
	WhitelistRejections atomic.Uint64
	RelayBytesUp        atomic.Uint64
	RelayBytesDown      atomic.Uint64
}

// NewServer 创建一个新的 Chimney 中继服务器。
func NewServer(config *Config, logger *slog.Logger) (*Server, error) {
	if config == nil {
		config = DefaultConfig()
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = HandshakeTimeout
	}
	if config.AuthReadTimeout == 0 {
		config.AuthReadTimeout = AuthReadTimeout
	}

	// 加载白名单：内联 YAML 优先于文件路径。
	var whitelistMgr *whitelist.Manager
	var loadErr error
	if config.IntentYAML != "" || config.EnforceYAML != "" {
		whitelistMgr, loadErr = whitelist.LoadManagerFromContent(
			[]byte(config.IntentYAML), []byte(config.EnforceYAML),
		)
	} else {
		whitelistMgr, loadErr = whitelist.LoadManager(config.IntentFile, config.EnforceFile)
	}
	if loadErr != nil {
		logger.Warn("failed to load whitelist, using empty", "error", loadErr)
		whitelistMgr = whitelist.NewManager(whitelist.NewIntentLayer(), whitelist.NewEnforceLayer())
	}
	logger.Debug("whitelist loaded",
		"intent_snis", whitelistMgr.Intent.List(),
		"enforce_entries", len(whitelistMgr.Enforce.Entries),
		"inline_intent_len", len(config.IntentYAML),
		"inline_enforce_len", len(config.EnforceYAML),
	)

	// 创建用于认证的用户存储。
	// 优先级：Users（显式 PSK 映射）> UserIDs（UUID 推导的 PSK）> PSK（单用户）。
	var userStore *auth.UserStore
	var userErr error
	switch {
	case len(config.Users) > 0:
		userStore, userErr = auth.NewUserStore(config.Users, config.TagLen)
	case len(config.UserIDs) > 0:
		userStore, userErr = auth.NewUserStoreFromIDs(config.UserIDs, config.TagLen)
	case config.PSK != "":
		userStore, userErr = auth.NewUserStore(map[string]string{"default": config.PSK}, config.TagLen)
	default:
		return nil, fmt.Errorf("relay: one of PSK, Users, or UserIDs must be configured")
	}
	if userErr != nil {
		return nil, fmt.Errorf("relay: failed to create user store: %w", userErr)
	}

	connectACL, err := newConnectACL(config.ConnectAllowCIDRs, config.ConnectDenyCIDRs, config.ConnectDenyPrivate)
	if err != nil {
		return nil, fmt.Errorf("relay: invalid CONNECT ACL: %w", err)
	}

	return &Server{
		config:       config,
		whitelistMgr: whitelistMgr,
		userStore:    userStore,
		stats:        &Stats{},
		logger:       logger,
		dialSem:      make(chan struct{}, MaxConcurrentBackendDials),
		connSem:      make(chan struct{}, MaxBackendConnsGlobal),
		connectACL:   connectACL,
	}, nil
}

// Start 启动中继服务器。
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("relay: failed to listen on %s: %w", s.config.ListenAddr, err)
	}
	s.listener = ln

	s.logger.Info("chimney relay listening",
		"addr", s.config.ListenAddr,
		"cloud_region", s.config.CloudRegion,
	)

	go s.acceptLoop()
	return nil
}

// Stop 停止中继服务器。
func (s *Server) Stop() error {
	s.closed.Store(true)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	return nil
}

// Stats 返回当前服务器统计信息。
func (s *Server) Stats() *Stats {
	return s.stats
}

// UserStore 返回用户存储，用于运行时用户管理。
func (s *Server) UserStore() *auth.UserStore {
	return s.userStore
}

// acceptLoop 接受传入的连接。
func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			s.logger.Error("accept failed", "error", err)
			continue
		}

		s.stats.TotalConnections.Add(1)
		s.stats.ActiveConnections.Add(1)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.stats.ActiveConnections.Add(-1)

			s.handleConnection(conn)
		}()
	}
}

// handleConnection 处理单个客户端连接。
func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// 为高并发 H2 多路复用调优 TCP 缓冲区。
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetReadBuffer(256 * 1024)
		tcpConn.SetWriteBuffer(256 * 1024)
		tcpConn.SetNoDelay(true)
	}

	logger := s.logger.With("remote", clientConn.RemoteAddr().String())
	logger.Debug("new connection")

	// 步骤 1：读取 ClientHello 并提取 SNI + ClientRandom
	clientConn.SetReadDeadline(time.Now().Add(s.config.HandshakeTimeout))
	clientHello, sni, clientRandom, err := s.readClientHello(clientConn)
	clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		logger.Debug("failed to read ClientHello", "error", err)
		s.passiveFallback(clientConn, nil, logger)
		return
	}

	logger = logger.With("sni", sni)

	// 步骤 2：白名单检查（关卡A + 关卡B）
	destIP, err := s.resolveDestination(sni)
	if err != nil {
		logger.Debug("failed to resolve SNI", "error", err)
		s.passiveFallback(clientConn, nil, logger)
		return
	}

	if err := s.whitelistMgr.CheckDestination(sni, destIP); err != nil {
		s.stats.WhitelistRejections.Add(1)
		logger.Debug("whitelist check failed", "error", err)
		s.passiveFallback(clientConn, nil, logger)
		return
	}

	// 步骤 3：连接到真实站点并转发握手
	siteConn, err := net.DialTimeout("tcp", net.JoinHostPort(destIP, "443"), s.config.HandshakeTimeout)
	if err != nil {
		logger.Debug("failed to connect to real site", "error", err, "dest_ip", destIP)
		s.passiveFallback(clientConn, nil, logger)
		return
	}
	defer siteConn.Close()

	// 将 ClientHello 转发到真实站点
	if _, err := siteConn.Write(clientHello); err != nil {
		logger.Debug("failed to forward ClientHello", "error", err)
		s.passiveFallback(clientConn, siteConn, logger)
		return
	}

	// 步骤 4：中继握手并提取 ServerRandom
	serverRandom, firstAppData, err := s.relayHandshake(clientConn, siteConn, logger)
	if err != nil {
		logger.Debug("handshake relay failed", "error", err)
		s.passiveFallback(clientConn, siteConn, logger)
		return
	}

	hexDump := hex.EncodeToString(firstAppData)
	if len(hexDump) > 64 {
		hexDump = hexDump[:64] + "..."
	}
	logger.Debug("handshake relayed",
		"server_random", hex.EncodeToString(serverRandom),
		"client_random", hex.EncodeToString(clientRandom),
		"first_app_data_len", len(firstAppData),
		"first_app_data_hex", hexDump,
	)

	// 步骤 5：若未捕获到第一个应用数据，则透传转发
	if len(firstAppData) == 0 {
		logger.Debug("no first app data captured, forwarding transparently")
		s.forwardToSite(clientConn, siteConn, nil, logger)
		return
	}

	// 步骤 6：调包前的启发式检查。
	// 认证帧格式为：[key_hint (4)] [tag (tagLen)]，因此 +4 为提示。
	expectedAuthRecordMin := 5 + 4 + auth.DefaultTagLen + len(h2engine.H2ConnectionPreface)
	if len(firstAppData) < expectedAuthRecordMin {
		logger.Debug("first app data too short for Chimney, forwarding transparently",
			"record_len", len(firstAppData),
		)
		s.forwardToSite(clientConn, siteConn, firstAppData, logger)
		return
	}

	// 步骤 7：尝试调包。认证标签在 performSwap 内部
	// 从认证帧中提取 key_hint 后进行验证。
	logger.Info("attempting swap")

	if err := s.performSwap(clientConn, siteConn, sni, serverRandom, clientRandom, firstAppData, logger); err != nil {
		logger.Debug("swap failed", "error", err)
		s.stats.AuthFailures.Add(1)
		// performSwap 的预检查失败，未消耗 clientConn 中的数据——
		// firstAppData 完好无损，可以转发。
		s.forwardToSite(clientConn, siteConn, firstAppData, logger)
		return
	}
}

// readClientHello 从客户端连接读取 ClientHello。
func (s *Server) readClientHello(conn net.Conn) ([]byte, string, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, "", nil, fmt.Errorf("read record header: %w", err)
	}

	if header[0] != 0x16 {
		return nil, "", nil, fmt.Errorf("expected handshake record, got 0x%02x", header[0])
	}

	handshakeLen := int(header[3])<<8 | int(header[4])
	handshakeMsg := make([]byte, handshakeLen)
	if _, err := io.ReadFull(conn, handshakeMsg); err != nil {
		return nil, "", nil, fmt.Errorf("read handshake message: %w", err)
	}

	clientHello := append(header, handshakeMsg...)

	sni := extractSNI(handshakeMsg)
	if sni == "" {
		return clientHello, "", nil, errors.New("no SNI in ClientHello")
	}

	clientRandomExtractor := &auth.ClientRandomExtractor{}
	clientRandom, err := clientRandomExtractor.ExtractFromClientHello(handshakeMsg)
	if err != nil {
		return clientHello, sni, nil, fmt.Errorf("extract ClientRandom: %w", err)
	}

	return clientHello, sni, clientRandom, nil
}

// relayHandshake 在客户端和真实站点之间中继 TLS 握手，
// 监控 TLS 记录类型以确定握手何时结束。
//
// 它双向转发所有握手记录（0x16）和 ChangeCipherSpec（0x14）。
// 当第一个应用数据记录（0x17）从客户端到达时，停止转发并返回缓冲的记录。
// 站点连接保持存活——调用者决定是调包（Chimney 模式）还是继续透传转发。
func (s *Server) relayHandshake(clientConn, siteConn net.Conn, logger *slog.Logger) (serverRandom []byte, firstAppData []byte, err error) {
	type result struct {
		serverRandom []byte
		firstAppData []byte
		err          error
	}

	resCh := make(chan result, 1)

	go func() {
		var sr []byte
		var fa []byte

		quit := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		// 服务器 → 客户端：转发所有内容，提取 ServerRandom
		go func() {
			defer wg.Done()
			buf := make([]byte, TCPBufferSize)
			serverBuf := make([]byte, 0, 4096)

			for {
				n, readErr := siteConn.Read(buf)
				if n > 0 {
					if sr == nil {
						serverBuf = append(serverBuf, buf[:n]...)
						extractor := &auth.ServerRandomExtractor{}
						if extracted, e := extractor.ExtractFromTLSRecords(serverBuf); e == nil {
							sr = extracted
							logger.Debug("extracted ServerRandom", "sr", hex.EncodeToString(sr))
						}
					}
					if _, writeErr := clientConn.Write(buf[:n]); writeErr != nil {
						return
					}
				}
				if readErr != nil {
					select {
					case <-quit:
						return
					default:
					}
					return
				}
				select {
				case <-quit:
					return
				default:
				}
			}
		}()

		// 客户端 → 服务器：转发握手记录，拦截第一个 0x17
		go func() {
			defer wg.Done()
			buf := make([]byte, TCPBufferSize)
			recordBuf := make([]byte, 0, 65536)

			for {
				n, readErr := clientConn.Read(buf)
				if n > 0 {
					recordBuf = append(recordBuf, buf[:n]...)

					// 从缓冲区解析完整的 TLS 记录
					for len(recordBuf) >= 5 {
						recordType := recordBuf[0]
						recordLen := int(recordBuf[3])<<8 | int(recordBuf[4])
						total := 5 + recordLen
						if len(recordBuf) < total {
							break
						}

						if recordType == 0x17 {
							// 第一个应用数据——捕获它以及所有后续数据。
							// uTLS 可能在 ChimneyRecord 之前发送握手后的 0x17 记录。
							// 读取所有后续数据。
							fa = make([]byte, len(recordBuf))
							copy(fa, recordBuf)
							faHash := sha256.Sum256(fa)
							logger.Debug("relayHandshake captured first 0x17",
								"recordBuf_sha256", hex.EncodeToString(faHash[:]),
								"recordBuf_len", len(fa),
							)
							close(quit)
							siteConn.SetReadDeadline(time.Now())

							// 读取第一个 0x17 之后的剩余数据
							origFaLen := len(fa)
							clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
							for {
								n2, rdErr := clientConn.Read(buf)
								if n2 > 0 {
									fa = append(fa, buf[:n2]...)
								}
								if rdErr != nil {
									break
								}
							}
							clientConn.SetReadDeadline(time.Time{})
							faHash2 := sha256.Sum256(fa)
							logger.Debug("relayHandshake drain complete",
								"fa_sha256", hex.EncodeToString(faHash2[:]),
								"fa_len", len(fa),
								"drained", len(fa)-origFaLen,
							)
							return
						}

						// 将握手/CCS 记录转发到站点
						if _, writeErr := siteConn.Write(recordBuf[:total]); writeErr != nil {
							return
						}
						recordBuf = recordBuf[total:]
					}
				}
				if readErr != nil {
					select {
					case <-quit:
						return
					default:
					}
					return
				}
				select {
				case <-quit:
					return
				default:
				}
			}
		}()

		wg.Wait()

		// 清除关闭期间设置的任何截止时间
		clientConn.SetReadDeadline(time.Time{})
		siteConn.SetReadDeadline(time.Time{})

		resCh <- result{sr, fa, nil}
	}()

	select {
	case res := <-resCh:
		if res.serverRandom == nil {
			return nil, nil, fmt.Errorf("failed to extract ServerRandom")
		}
		return res.serverRandom, res.firstAppData, nil
	case <-time.After(s.config.HandshakeTimeout):
		siteConn.Close()
		return nil, nil, ErrHandshakeTimeout
	}
}

// forwardToSite 继续将流量转发到真实站点。
func (s *Server) forwardToSite(clientConn, siteConn net.Conn, bufferedData []byte, logger *slog.Logger) {
	if len(bufferedData) > 0 {
		if _, err := siteConn.Write(bufferedData); err != nil {
			logger.Debug("failed to forward buffered data", "error", err)
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, TCPBufferSize)
		n, _ := io.CopyBuffer(siteConn, clientConn, buf)
		s.stats.RelayBytesUp.Add(uint64(n))
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, TCPBufferSize)
		n, _ := io.CopyBuffer(clientConn, siteConn, buf)
		s.stats.RelayBytesDown.Add(uint64(n))
	}()

	wg.Wait()
	logger.Debug("forwarding to site complete")
}

// prependConn 包装一个 net.Conn，在读取时前置一个数据前缀。
// 用于重新注入已从连接中消耗的数据。
type prependConn struct {
	net.Conn
	prefix    []byte
	prefixOff int
}

func (c *prependConn) Read(b []byte) (int, error) {
	if c.prefixOff < len(c.prefix) {
		n := copy(b, c.prefix[c.prefixOff:])
		c.prefixOff += n
		return n, nil
	}
	return c.Conn.Read(b)
}

// performSwap 在认证成功后执行调包操作。
func (s *Server) performSwap(clientConn, siteConn net.Conn, sni string, serverRandom, clientRandom, firstAppData []byte, logger *slog.Logger) error {
	// siteConn 在认证验证成功之前保持存活。
	// 若我们在记录 "swap complete" 之前返回错误，调用者
	// 可以回退到透传转发。

	// 收集所有要尝试的派生器：先显式 PSK，然后是所有用户派生器。
	var allDerivers []*keyderiv.Deriver
	if s.config.PSK != "" {
		d, err := keyderiv.NewDeriverFromHex(s.config.PSK)
		if err != nil {
			return fmt.Errorf("create deriver: %w", err)
		}
		allDerivers = append(allDerivers, d)
	}
	if s.userStore != nil && s.userStore.Count() > 0 {
		allDerivers = append(allDerivers, s.userStore.GetAllDerivers()...)
	}
	if len(allDerivers) == 0 {
		return fmt.Errorf("no derivers available (PSK empty and no users)")
	}

	// 扫描 firstAppData 寻找有效的 ChimneyRecord，尝试每个派生器。
	// uTLS 可能在 ChimneyRecord 之前发送了握手后的 0x17 记录，
	// 因此我们遍历 TLS 记录并逐个测试。
	var chimneyRecord, preludeRecords []byte
	var matchedDeriver *keyderiv.Deriver
	for _, d := range allDerivers {
		chimneyRecord, preludeRecords = findChimneyRecord(firstAppData, d, serverRandom, clientRandom, logger)
		if chimneyRecord != nil {
			matchedDeriver = d
			break
		}
	}

	// 若尚未找到，ChimneyRecord 可能还未到达
	//（客户端有自己的 drain+encode 过程，之后才写入）。
	// 从 clientConn 读取更多数据并重试。
	if chimneyRecord == nil && len(firstAppData) < 4096 {
		logger.Debug("ChimneyRecord not in initial buffer, reading more from client")
		clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		readBuf := make([]byte, TCPBufferSize)
		for i := 0; i < 3 && chimneyRecord == nil; i++ {
			n, rdErr := clientConn.Read(readBuf)
			if n > 0 {
				firstAppData = append(firstAppData, readBuf[:n]...)
				for _, d := range allDerivers {
					chimneyRecord, preludeRecords = findChimneyRecord(firstAppData, d, serverRandom, clientRandom, logger)
					if chimneyRecord != nil {
						matchedDeriver = d
						break
					}
				}
			}
			if rdErr != nil {
				break
			}
		}
		clientConn.SetReadDeadline(time.Time{})
	}

	if chimneyRecord == nil {
		logger.Debug("no ChimneyRecord found in first app data, falling back to forwarding")
		return fmt.Errorf("not a Chimney record: no valid record in %d bytes", len(firstAppData))
	}

	sendKey, recvKey, err := matchedDeriver.DeriveDirectionalKeys(serverRandom, clientRandom)
	if err != nil {
		return fmt.Errorf("derive directional keys: %w", err)
	}
	sendNonceBase, err := matchedDeriver.DeriveNonceBase(serverRandom, clientRandom)
	if err != nil {
		return fmt.Errorf("derive send nonce base: %w", err)
	}
	recvNonceBase, err := matchedDeriver.DeriveNonceBase(clientRandom, serverRandom)
	if err != nil {
		return fmt.Errorf("derive recv nonce base: %w", err)
	}

	logger.Debug("directional keys derived (RELAY)",
		"sendKey", hex.EncodeToString(sendKey[:4]),
		"recvKey", hex.EncodeToString(recvKey[:4]),
		"sendNonce", hex.EncodeToString(sendNonceBase),
		"recvNonce", hex.EncodeToString(recvNonceBase),
	)
	// 将任何前奏（非 Chimney）记录转发到真实站点。
	if len(preludeRecords) > 0 {
		logger.Debug("forwarding prelude records to site", "bytes", len(preludeRecords))
		if _, err := siteConn.Write(preludeRecords); err != nil {
			logger.Debug("failed to forward prelude records", "error", err)
		}
	}

	logger.Debug("pre-check: found valid ChimneyRecord", "offset", len(preludeRecords), "len", len(chimneyRecord))

	// 为实际的 I/O 创建一个新的编解码器（nonce 从 0 开始）。
	// 之前的编解码器仅用于扫描。
	codec, err := record.NewCodecWithDirectionalKeys(recvKey, recvNonceBase, sendKey, sendNonceBase)
	if err != nil {
		kSess, _ := matchedDeriver.DeriveSessionKey(serverRandom, clientRandom)
		nonceBase, _ := matchedDeriver.DeriveNonceBase(serverRandom, clientRandom)
		codec, err = record.NewCodec(kSess, nonceBase)
		if err != nil {
			return fmt.Errorf("create codec: %w", err)
		}
	}

	// 包装 clientConn，从第一个 chimney record 开始重放所有数据。
	// findChimneyRecord 可能在客户端背靠背发送记录时（例如 H2
	// preface + SETTINGS ACK + auth DATA）消费了 chimney record 之后
	// 更多的 TLS 记录。丢弃这些字节会导致永久性的 AEAD 计数器不同步。
	tunnelPrefix := firstAppData[len(preludeRecords):]
	if len(tunnelPrefix) > len(chimneyRecord) {
		logger.Debug("swap buffer includes trailing records",
			"chimney_record", len(chimneyRecord),
			"extra_bytes", len(tunnelPrefix)-len(chimneyRecord))
	}
	tpHash := sha256.Sum256(tunnelPrefix)
	logger.Debug("tunnelPrefix hash",
		"sni", sni,
		"tunnelPrefix_sha256", hex.EncodeToString(tpHash[:]),
		"tunnelPrefix_len", len(tunnelPrefix),
		"prelude_len", len(preludeRecords),
		"firstAppData_len", len(firstAppData),
	)
	wrappedReader := &prependConn{Conn: clientConn, prefix: tunnelPrefix}
	recReader := record.NewRecordReader(wrappedReader, codec)
	recWriter := record.NewRecordWriter(wrappedReader, codec)
	defer recWriter.Close()

	settings := h2engine.DefaultSettings()
	if siteEntry, ok := s.whitelistMgr.GetSiteInfo(sni); ok {
		if siteEntry.SettingsSnapshot != nil {
			settings = applySettingsSnapshot(settings, siteEntry.SettingsSnapshot)
			logger.Debug("loaded site settings", "sni", sni)
		}
	}

	h2Eng := h2engine.NewEngine(settings, codec)
	h2Eng.SetRecordIO(recReader, recWriter)

	logger.Debug("starting AcceptAsServer, reading client H2 preface")

	if err := h2Eng.AcceptAsServer(); err != nil {
		return fmt.Errorf("H2 accept failed: %w", err)
	}

	// 完成 H2 握手：读取客户端的 SETTINGS ACK（由
	// completeH2Handshake 在认证标签之前发送）。客户端发送：
	//   1. Preface + SETTINGS  （由 AcceptAsServer 消费）
	//   2. SETTINGS ACK
	//   3. 认证标签 DATA 帧
	// 我们必须在读取认证标签之前消耗掉 ACK。
	ackFh, _, err := h2Eng.ReadFrame()
	if err != nil {
		logger.Debug("failed to read client SETTINGS ACK", "error", err)
		return fmt.Errorf("H2 handshake complete: %w", err)
	}
	if ackFh.Type == h2engine.FrameSettings && ackFh.Flags&h2engine.FlagAck != 0 {
		logger.Debug("received client SETTINGS ACK")
	}

	var fh *h2engine.FrameHeader
	var payload []byte
	fh, payload, err = h2Eng.ReadFrame()
	if err != nil {
		logger.Debug("failed to read post-swap auth frame", "error", err)
		return fmt.Errorf("post-swap auth read: %w", err)
	}

	if fh.Type == h2engine.FrameData {
		tagLen := s.userStore.TagLen()
		if len(payload) < 4+tagLen {
			logger.Debug("auth frame too short", "got", len(payload), "need", 4+tagLen)
			return ErrAuthFailed
		}

		hint, err := auth.ExtractKeyHint(payload)
		if err != nil {
			logger.Debug("failed to extract key hint", "error", err)
			return ErrAuthFailed
		}

		tagFromClient, err := auth.ExtractTagFromHintFrame(payload, tagLen)
		if err != nil {
			logger.Debug("failed to extract tag from hint frame", "error", err)
			return ErrAuthFailed
		}

		ok, err := s.userStore.VerifyTag(hint, serverRandom, clientRandom, tagFromClient)
		if err != nil {
			logger.Debug("auth verification error", "error", err)
			return ErrAuthFailed
		}
		if !ok {
			logger.Debug("post-swap auth tag mismatch", "hint", fmt.Sprintf("%x", hint))
			return ErrAuthFailed
		}
		logger.Debug("post-swap auth verified successfully", "hint", fmt.Sprintf("%x", hint))
	} else {
		logger.Debug("expected DATA frame for auth, got type", "type", fh.Type)
		return ErrAuthFailed
	}

	// 认证已验证——现在可以安全地切断真实站点连接。
	siteConn.Close()
	s.stats.AuthenticatedSwaps.Add(1)
	logger.Info("swap complete, H2 tunnel established")

	return s.handleTunnel(h2Eng, logger)
}

// MaxBackendConnsGlobal 限制所有 H2 隧道中打开的后端连接总数，
// 以防止压垮后端服务器的监听积压队列。
const MaxBackendConnsGlobal = 128

// maxPendingBytesPerStream 限制单个等待中的流的缓冲数据量。
// 超出此限制时，流会被 RST_STREAM 拒绝，以防止高并发上传场景下
// 大量流阻塞 connSem 导致内存溢出。
const maxPendingBytesPerStream = 256 * 1024

// maxPendingStreams 限制等待后端连接的流的数量。
// 超出此限制时，新的 CONNECT 请求将被 REFUSED_STREAM 拒绝。
const maxPendingStreams = 256

// maxTunnelDataChunk 为 Chimney 隧道命令前缀留出一个字节，使得
// 每个 H2 DATA 帧在分片后携带自己的 0x02 DATA 命令。
const maxTunnelDataChunk = 16*1024 - 1

// tunnelConnPool 管理隧道流的后端连接。
type tunnelConnPool struct {
	mu            sync.Mutex
	streams       map[uint32]net.Conn
	writeChs      map[uint32]chan<- []byte // 每个流的写入通道
	pending       map[uint32]*pendingStream
	backendDialer func(ctx context.Context, network, addr string) (net.Conn, error)
	dialSem       chan struct{} // 限制并发的后端拨号（跨隧道共享）
	connSem       chan struct{} // 限制打开的后端连接总数（跨隧道共享）
	connectACL    *connectACL
}

type pendingStream struct {
	ctx    context.Context
	cancel context.CancelFunc
	bufs   [][]byte
}

type connectACL struct {
	allowCIDRs  []*net.IPNet
	denyCIDRs   []*net.IPNet
	denyPrivate bool
}

func newConnectACL(allowCIDRs, denyCIDRs []string, denyPrivate bool) (*connectACL, error) {
	if len(allowCIDRs) == 0 && len(denyCIDRs) == 0 && !denyPrivate {
		return nil, nil
	}

	allow, err := parseConnectCIDRs("allow", allowCIDRs)
	if err != nil {
		return nil, err
	}
	deny, err := parseConnectCIDRs("deny", denyCIDRs)
	if err != nil {
		return nil, err
	}
	return &connectACL{
		allowCIDRs:  allow,
		denyCIDRs:   deny,
		denyPrivate: denyPrivate,
	}, nil
}

func parseConnectCIDRs(name string, cidrs []string) ([]*net.IPNet, error) {
	parsed := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("%s CIDR %q: %w", name, cidr, err)
		}
		parsed = append(parsed, ipNet)
	}
	return parsed, nil
}

func (a *connectACL) resolveDialAddr(ctx context.Context, dest string) (string, error) {
	if a == nil {
		return dest, nil
	}

	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		return "", fmt.Errorf("invalid CONNECT destination %q: %w", dest, err)
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return "", fmt.Errorf("resolve CONNECT destination %q: %w", host, err)
		}
		ips = make([]net.IP, 0, len(addrs))
		for _, addr := range addrs {
			ips = append(ips, addr.IP)
		}
	}

	for _, ip := range ips {
		if a.allows(ip) {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	return "", fmt.Errorf("CONNECT destination %q rejected by ACL", dest)
}

func (a *connectACL) allows(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if a.denyPrivate && isPrivateConnectTarget(ip) {
		return false
	}
	for _, cidr := range a.denyCIDRs {
		if cidr.Contains(ip) {
			return false
		}
	}
	if len(a.allowCIDRs) == 0 {
		return true
	}
	for _, cidr := range a.allowCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateConnectTarget(ip net.IP) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

func newTunnelConnPool(backendDialer func(ctx context.Context, network, addr string) (net.Conn, error), dialSem, connSem chan struct{}, connectACL *connectACL) *tunnelConnPool {
	return &tunnelConnPool{
		streams:       make(map[uint32]net.Conn),
		writeChs:      make(map[uint32]chan<- []byte),
		pending:       make(map[uint32]*pendingStream),
		backendDialer: backendDialer,
		dialSem:       dialSem,
		connSem:       connSem,
		connectACL:    connectACL,
	}
}

func (p *tunnelConnPool) getOrCreate(streamID uint32) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conn, ok := p.streams[streamID]; ok {
		return conn, nil
	}
	return nil, fmt.Errorf("no backend connection for stream %d", streamID)
}

func (p *tunnelConnPool) createForStream(streamID uint32, dest string) (net.Conn, error) {
	p.mu.Lock()
	pending := p.pending[streamID]
	p.mu.Unlock()
	if pending == nil {
		return nil, errStreamCanceled
	}

	dialAddr, err := p.connectACL.resolveDialAddr(pending.ctx, dest)
	if err != nil {
		return nil, err
	}

	// 首先获取连接槽位——当隧道已有 maxBackendConnsPerTunnel
	// 个打开的后端连接时，这提供了背压机制。
	select {
	case p.connSem <- struct{}{}:
	case <-pending.ctx.Done():
		return nil, errStreamCanceled
	}

	// 获取拨号信号量，以防止同时的 TCP 拨号压垮后端服务器的监听积压队列。
	select {
	case p.dialSem <- struct{}{}:
	case <-pending.ctx.Done():
		<-p.connSem
		return nil, errStreamCanceled
	}
	defer func() { <-p.dialSem }()

	var conn net.Conn
	if p.backendDialer != nil {
		conn, err = p.backendDialer(pending.ctx, "tcp", dialAddr)
	} else {
		dialer := net.Dialer{Timeout: 10 * time.Second}
		conn, err = dialer.DialContext(pending.ctx, "tcp", dialAddr)
	}
	if err != nil {
		<-p.connSem // 拨号失败时释放槽位
		return nil, fmt.Errorf("dial backend %s: %w", dialAddr, err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	p.mu.Lock()
	if p.pending[streamID] == nil || p.pending[streamID].ctx.Err() != nil {
		p.mu.Unlock()
		conn.Close()
		<-p.connSem
		return nil, errStreamCanceled
	}
	p.streams[streamID] = conn
	p.mu.Unlock()
	return conn, nil
}

func (p *tunnelConnPool) closeStream(streamID uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if pending, ok := p.pending[streamID]; ok {
		pending.cancel()
		delete(p.pending, streamID)
	}
	if conn, ok := p.streams[streamID]; ok {
		conn.Close()
		delete(p.streams, streamID)
	}
	if ch, ok := p.writeChs[streamID]; ok {
		close(ch)
		delete(p.writeChs, streamID)
	}
}

func (p *tunnelConnPool) addPending(streamID uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	p.pending[streamID] = &pendingStream{ctx: ctx, cancel: cancel}
}

func (p *tunnelConnPool) bufferForPending(streamID uint32, data []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	pending, ok := p.pending[streamID]
	if !ok || pending.ctx.Err() != nil {
		return false
	}
	total := 0
	for _, d := range pending.bufs {
		total += len(d)
	}
	if total+len(data) > maxPendingBytesPerStream {
		return false
	}
	d := make([]byte, len(data))
	copy(d, data)
	pending.bufs = append(pending.bufs, d)
	return true
}

func (p *tunnelConnPool) isPending(streamID uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.pending[streamID]
	return ok
}

func (p *tunnelConnPool) pendingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending)
}

func (p *tunnelConnPool) removePending(streamID uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pending, ok := p.pending[streamID]; ok {
		pending.cancel()
	}
	delete(p.pending, streamID)
}

func (p *tunnelConnPool) flushPending(streamID uint32, writeCh chan<- []byte) {
	p.mu.Lock()
	var bufs [][]byte
	if pending := p.pending[streamID]; pending != nil {
		bufs = pending.bufs
		pending.cancel()
	}
	delete(p.pending, streamID)
	p.mu.Unlock()
	for _, data := range bufs {
		writeCh <- data
	}
}

// registerWriteCh 为流创建一个带缓冲的写入通道并返回它。
// 调用者必须启动一个写入 goroutine 来消费此通道。
func (p *tunnelConnPool) registerWriteCh(streamID uint32) chan []byte {
	ch := make(chan []byte, 64)
	p.mu.Lock()
	p.writeChs[streamID] = ch
	p.mu.Unlock()
	return ch
}

// writeToStream 通过通道将数据发送到流的写入 goroutine。
// 阻塞直到写入 goroutine 接受数据，提供自然的
// 按流级别的背压，而不是阻塞整个隧道。
// 如果流未注册或已被并发关闭，则返回 false。
func (p *tunnelConnPool) writeToStream(streamID uint32, data []byte) (sent bool) {
	p.mu.Lock()
	ch, ok := p.writeChs[streamID]
	p.mu.Unlock()
	if !ok {
		return false
	}
	d := make([]byte, len(data))
	copy(d, data)
	// closeStream 可能在 map 读取和此发送之间关闭 ch；恢复 panic。
	defer func() {
		if r := recover(); r != nil {
			sent = false
		}
	}()
	ch <- d
	return true
}

// writeBackend 消费写入通道并将每个数据块写入后端。
// 在自己的 goroutine 中运行，与 readBackend 配对。
func (s *Server) writeBackend(streamID uint32, backendConn net.Conn, ch <-chan []byte, logger *slog.Logger, pool *tunnelConnPool) {
	for data := range ch {
		if _, err := backendConn.Write(data); err != nil {
			logger.Debug("backend write failed", "error", err, "stream_id", streamID)
			pool.closeStream(streamID)
			return
		}
	}
}

func (p *tunnelConnPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for id, conn := range p.streams {
		conn.Close()
		delete(p.streams, id)
	}
	for id, ch := range p.writeChs {
		close(ch)
		delete(p.writeChs, id)
	}
	for id, pending := range p.pending {
		pending.cancel()
		delete(p.pending, id)
	}
}

// ---------------------------------------------------------------------------
// UDP 后端——用于 Chimney UDP 子流的按流 UDP 套接字
// ---------------------------------------------------------------------------

// udpBackend 管理一个 Chimney UDP 子流的 UDP 套接字。
// 客户端哈希五元组来选择流；中继为每个流创建一个 UDP
// 套接字以处理发往任意目标的数据报。
type udpBackend struct {
	conn     *net.UDPConn
	streamID uint32
	h2Eng    *h2engine.Engine
	logger   *slog.Logger
	quit     chan struct{}
}

// startUDPBackend 创建一个 UDP 套接字并开始将接收到的
// 数据报作为 H2 DATA 帧转发回客户端。
func (s *Server) startUDPBackend(streamID uint32, h2Eng *h2engine.Engine, logger *slog.Logger) (*udpBackend, error) {
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("relay: udp listen: %w", err)
	}
	ub := &udpBackend{
		conn:     udpConn,
		streamID: streamID,
		h2Eng:    h2Eng,
		logger:   logger,
		quit:     make(chan struct{}),
	}
	go ub.readLoop()
	return ub, nil
}

// readLoop 从 UDP 套接字读取数据报并将其发送到客户端。
// 线路格式：[0x04 cmd][1B addrType][addr][2B port][payload]
func (ub *udpBackend) readLoop() {
	buf := make([]byte, 65536)
	const readTimeout = 30 * time.Second
	const idleKillTimeout = 5 * time.Minute
	lastPacket := time.Now()
	for {
		select {
		case <-ub.quit:
			return
		default:
		}
		ub.conn.SetReadDeadline(time.Now().Add(readTimeout))
		n, remoteAddr, err := ub.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if time.Since(lastPacket) >= idleKillTimeout {
					ub.logger.Debug("udp backend idle timeout, closing", "stream_id", ub.streamID)
					return
				}
				continue
			}
			ub.logger.Debug("udp backend read error", "stream_id", ub.streamID, "error", err)
			return
		}
		lastPacket = time.Now()
		frame := encodeUDPResponse(remoteAddr, buf[:n])
		if frame == nil {
			continue
		}
		if err := ub.h2Eng.WriteData(ub.streamID, frame, false); err != nil {
			ub.logger.Debug("udp backend write frame error", "stream_id", ub.streamID, "error", err)
			return
		}
	}
}

// encodeUDPResponse 构建 UDP 响应数据报的线路格式。
func encodeUDPResponse(addr *net.UDPAddr, payload []byte) []byte {
	ip := addr.IP.To4()
	if ip != nil {
		buf := make([]byte, 1+1+4+2+len(payload))
		buf[0] = 0x04
		buf[1] = 0x01 // IPv4
		copy(buf[2:6], ip)
		buf[6] = byte(addr.Port >> 8)
		buf[7] = byte(addr.Port)
		copy(buf[8:], payload)
		return buf
	}
	ip6 := addr.IP.To16()
	if ip6 != nil {
		buf := make([]byte, 1+1+16+2+len(payload))
		buf[0] = 0x04
		buf[1] = 0x04 // IPv6
		copy(buf[2:18], ip6)
		buf[18] = byte(addr.Port >> 8)
		buf[19] = byte(addr.Port)
		copy(buf[20:], payload)
		return buf
	}
	return nil
}

// parseUDPAddr 从 UDP DATA 帧负载中提取目标地址
// （0x04 命令字节之后的字节）。
func parseUDPAddr(cmdData []byte) (*net.UDPAddr, []byte, error) {
	if len(cmdData) < 3 {
		return nil, nil, fmt.Errorf("relay: truncated UDP frame")
	}
	var host string
	var rest []byte
	switch cmdData[0] {
	case 0x01: // IPv4
		if len(cmdData) < 7 {
			return nil, nil, fmt.Errorf("relay: truncated IPv4 UDP frame")
		}
		port := int(cmdData[5])<<8 | int(cmdData[6])
		host = net.IP(cmdData[1:5]).String()
		rest = cmdData[7:]
		return &net.UDPAddr{IP: net.ParseIP(host), Port: port}, rest, nil
	case 0x03: // 域名
		if len(cmdData) < 3 {
			return nil, nil, fmt.Errorf("relay: truncated domain UDP frame")
		}
		nameLen := int(cmdData[1])
		if nameLen == 0 {
			return nil, nil, fmt.Errorf("relay: empty UDP domain")
		}
		addrEnd := 2 + nameLen
		if len(cmdData) < addrEnd+2 {
			return nil, nil, fmt.Errorf("relay: truncated domain UDP frame")
		}
		port := int(cmdData[addrEnd])<<8 | int(cmdData[addrEnd+1])
		host = string(cmdData[2 : 2+nameLen])
		rest = cmdData[addrEnd+2:]
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(port)))
		if err != nil {
			return nil, nil, fmt.Errorf("relay: resolve UDP domain %q: %w", host, err)
		}
		return addr, rest, nil
	case 0x04: // IPv6
		if len(cmdData) < 19 {
			return nil, nil, fmt.Errorf("relay: truncated IPv6 UDP frame")
		}
		port := int(cmdData[17])<<8 | int(cmdData[18])
		host = net.IP(cmdData[1:17]).String()
		rest = cmdData[19:]
		return &net.UDPAddr{IP: net.ParseIP(host), Port: port}, rest, nil
	default:
		return nil, nil, fmt.Errorf("relay: unknown UDP addr type %d", cmdData[0])
	}
}

func (ub *udpBackend) close() {
	select {
	case <-ub.quit:
	default:
		close(ub.quit)
	}
	ub.conn.Close()
}

// wantsTrafficProfile 返回是否需要构建流量 profile。
// 下行塑形(StealthMode)需要它做记录大小/节奏采样;上行逐帧 pacing
// (EnableProfiling)也需要它。任一开启即构建,从而解耦二者:关掉
// EnableProfiling 提升上传时,StealthMode 的下行记录伪装仍有 profile 可用。
func wantsTrafficProfile(cfg *Config) bool {
	return cfg.EnableProfiling || cfg.StealthMode
}

// handleTunnel 在调包后处理 H2 隧道，带流量画像调速。
func (s *Server) handleTunnel(h2Eng *h2engine.Engine, logger *slog.Logger) error {
	pool := newTunnelConnPool(s.config.BackendDialer, s.dialSem, s.connSem, s.connectACL)
	defer pool.closeAll()

	udpBackends := make(map[uint32]*udpBackend)
	defer func() {
		for _, ub := range udpBackends {
			ub.close()
		}
	}()

	// trafficProfile 供两处使用,但解耦控制:
	//   - 下行塑形器:StealthMode 下始终需要 profile 来采样真实记录大小/节奏;
	//   - 上行逐帧 pacing:仅 EnableProfiling 时启用(它会拖慢上传)。
	// 因此只要 EnableProfiling 或 StealthMode 任一开启就构建 profile,
	// 这样关掉 EnableProfiling 提升上传的同时,下行记录伪装不受影响。
	var trafficProfile *profile.Model
	if wantsTrafficProfile(s.config) {
		trafficProfile = profile.DefaultModel()
	}

	// 下行流量塑形(stealth):记录 padding + 按 profile 节奏的下行注水。
	shaper := newDownlinkShaper(s.config, trafficProfile)
	injectorDone := make(chan struct{})
	defer close(injectorDone)
	if shaper.enabled {
		go shaper.runInjector(h2Eng, injectorDone)
	}

	for {
		fh, payload, err := h2Eng.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				logger.Debug("tunnel closed by client")
				return nil
			}
			sealerSeq, openerSeq := h2Eng.CodecSeqs()
			logger.Debug("frame read error", "error", err,
				"sealer_seq", sealerSeq, "opener_seq", openerSeq)
			return err
		}

		// 丢弃保留流的帧（填充、稀释）——它们仅用于
		// 维持流量形态，不属于隧道数据。
		if h2engine.IsReservedStream(fh.StreamID) {
			continue
		}

		switch fh.Type {
		case h2engine.FrameData:
			if len(payload) < 1 {
				continue
			}
			cmd := payload[0]
			cmdData := payload[1:]

			// 如果流已有 TCP 后端，在考虑 UDP 命令之前通过
			// 按流写入通道分发。TCP 负载由客户端添加命令前缀，
			// 但原始回退数据可能以 0x04 开头，不得解析为 UDP。
			if _, err := pool.getOrCreate(fh.StreamID); err == nil {
				if cmd == 0x03 {
					logger.Debug("CLOSE stream", "stream_id", fh.StreamID)
					pool.closeStream(fh.StreamID)
				} else if cmd == 0x02 {
					shaper.recordUp(len(cmdData))
					pool.writeToStream(fh.StreamID, cmdData)
				} else {
					shaper.recordUp(len(payload))
					pool.writeToStream(fh.StreamID, payload)
				}
				continue
			}

			// 现有的 UDP 流——发送数据报或关闭 UDP 套接字。
			if ub, exists := udpBackends[fh.StreamID]; exists {
				if cmd == 0x03 {
					ub.close()
					delete(udpBackends, fh.StreamID)
					continue
				}
				if cmd != 0x04 {
					continue
				}
				addr, data, err := parseUDPAddr(cmdData)
				if err != nil {
					logger.Debug("udp parse addr failed", "error", err)
					continue
				}
				if _, err := ub.conn.WriteToUDP(data, addr); err != nil {
					logger.Debug("udp sendto failed", "error", err)
				}
				continue
			}

			// 新的 UDP 流（0x04）——创建 UDP 套接字，发送数据报。
			if cmd == 0x04 {
				ub, exists := udpBackends[fh.StreamID]
				if !exists {
					var err error
					ub, err = s.startUDPBackend(fh.StreamID, h2Eng, logger)
					if err != nil {
						logger.Debug("udp backend creation failed", "error", err)
						continue
					}
					udpBackends[fh.StreamID] = ub
				}
				addr, data, err := parseUDPAddr(cmdData)
				if err != nil {
					logger.Debug("udp parse addr failed", "error", err)
					continue
				}
				if _, err := ub.conn.WriteToUDP(data, addr); err != nil {
					logger.Debug("udp sendto failed", "error", err)
				}
				continue
			}

			// 为 CONNECT 仍在进行中的流缓冲数据。
			// 拒绝超过每个流等待缓冲区限制的流，
			// 以防止在 connSem 满负荷期间内存溢出（OOM）。
			if pool.isPending(fh.StreamID) {
				if cmd == 0x03 {
					logger.Debug("CLOSE pending stream", "stream_id", fh.StreamID)
					pool.closeStream(fh.StreamID)
					continue
				}
				if !pool.bufferForPending(fh.StreamID, payload) {
					logger.Debug("pending buffer overflow, rejecting stream", "stream_id", fh.StreamID)
					rstFrame := h2engine.RSTStreamFrame(fh.StreamID, h2engine.H2ErrEnhanceYourCalm)
					h2Eng.WriteRawFrame(rstFrame)
					pool.removePending(fh.StreamID)
				}
				continue
			}

			// 尚无后端——期望 CONNECT（0x01）。
			// 当太多流已在等待后端槽位时拒绝——
			// 防止高负载下无界的内存增长。
			if cmd == 0x01 {
				if pool.pendingCount() >= maxPendingStreams {
					logger.Debug("too many pending streams, rejecting CONNECT", "stream_id", fh.StreamID)
					rstFrame := h2engine.RSTStreamFrame(fh.StreamID, h2engine.H2ErrRefusedStream)
					h2Eng.WriteRawFrame(rstFrame)
					continue
				}
				dest := string(cmdData)
				logger.Debug("CONNECT", "stream_id", fh.StreamID, "dest", dest)
				pool.addPending(fh.StreamID)
				go func(sid uint32, destination string) {
					backendConn, err := pool.createForStream(sid, destination)
					if err != nil {
						logger.Debug("backend connect failed", "error", err)
						pool.removePending(sid)
						rstFrame := h2engine.RSTStreamFrame(sid, h2engine.H2ErrRefusedStream)
						h2Eng.WriteRawFrame(rstFrame)
						return
					}
					defer func() { <-pool.connSem }()
					defer pool.closeStream(sid)
					if err := h2Eng.WriteData(sid, []byte{0x01}, false); err != nil {
						logger.Debug("failed to send CONNECT_OK", "error", err)
					}
					writeCh := pool.registerWriteCh(sid)
					go s.writeBackend(sid, backendConn, writeCh, logger, pool)
					pool.flushPending(sid, writeCh)
					s.readBackend(sid, backendConn, h2Eng, shaper, logger)
				}(fh.StreamID, dest)
			}

		case h2engine.FrameWindowUpdate:
		case h2engine.FramePing:
			// 收到客户端 PING(非 ACK)→ 原样回 PONG,供客户端探测隧道存活。
			if fh.Flags&h2engine.FlagAck == 0 {
				var op [8]byte
				copy(op[:], payload)
				if err := h2Eng.WriteRawFrame(h2engine.PingFrame(op, true)); err != nil {
					logger.Debug("ping ack write failed", "error", err)
					return err
				}
			}
		case h2engine.FrameRSTStream:
			logger.Debug("RST_STREAM", "stream_id", fh.StreamID)
			pool.closeStream(fh.StreamID)

		case h2engine.FrameGoAway:
			logger.Debug("GOAWAY received")
			return nil
		}

		// 上行逐帧 pacing:仅在 EnableProfiling 时启用。它对每个上行帧 sleep
		// 一个 profile 节奏延迟,会显著拖慢上传;StealthMode 单独保留下行伪装,
		// 故默认建议 EnableProfiling=false 以获得更快上传。
		if s.config.EnableProfiling && trafficProfile != nil {
			delay := trafficProfile.RecordDelay()
			time.Sleep(delay)
		}
	}
}

// readBackend 从后端连接读取数据，并以 H2 DATA 帧的形式发送回数据。
// shaper 对下行记录做 padding 并记账下行字节(stealth 模式);未启用时为空操作。
func (s *Server) readBackend(streamID uint32, backendConn net.Conn, h2Eng *h2engine.Engine, shaper *downlinkShaper, logger *slog.Logger) {
	buf := make([]byte, 64*1024)
	for {
		n, err := backendConn.Read(buf)
		if n > 0 {
			for offset := 0; offset < n; {
				chunkSize := n - offset
				if chunkSize > maxTunnelDataChunk {
					chunkSize = maxTunnelDataChunk
				}
				response := make([]byte, 1+chunkSize)
				response[0] = 0x02
				copy(response[1:], buf[offset:offset+chunkSize])

				if werr := shaper.writeResponse(h2Eng, streamID, response); werr != nil {
					logger.Debug("backend response write failed", "error", werr, "stream_id", streamID)
					return
				}
				offset += chunkSize
			}
		}
		if err != nil {
			if err != io.EOF {
				logger.Debug("backend read error", "error", err, "stream_id", streamID)
			}
			h2Eng.WriteData(streamID, []byte{0x03}, false)
			return
		}
	}
}

// applySettingsSnapshot 将捕获的站点 H2 SETTINGS 应用到引擎设置。
func applySettingsSnapshot(defaults *h2engine.Settings, snapshot map[string]interface{}) *h2engine.Settings {
	if defaults == nil {
		defaults = h2engine.DefaultSettings()
	}

	for key, val := range snapshot {
		var v uint32
		switch n := val.(type) {
		case int:
			v = uint32(n)
		case int64:
			v = uint32(n)
		case float64:
			v = uint32(n)
		case uint32:
			v = n
		default:
			continue
		}

		switch key {
		case "HEADER_TABLE_SIZE":
			defaults.HeaderTableSize = &v
		case "ENABLE_PUSH":
			defaults.EnablePush = &v
		case "MAX_CONCURRENT_STREAMS":
			defaults.MaxConcurrentStreams = &v
		case "INITIAL_WINDOW_SIZE":
			defaults.InitialWindowSize = &v
		case "MAX_FRAME_SIZE":
			defaults.MaxFrameSize = &v
			defaults.MaxFrameSizeActual = v
		case "MAX_HEADER_LIST_SIZE":
			defaults.MaxHeaderListSize = &v
		}
	}

	return defaults
}

// passiveFallback 处理白名单/认证检查失败的情况。
func (s *Server) passiveFallback(clientConn net.Conn, siteConn net.Conn, logger *slog.Logger) {
	if s.config.DefaultBackend != "" && siteConn == nil {
		backend, err := net.DialTimeout("tcp", s.config.DefaultBackend, 5*time.Second)
		if err != nil {
			logger.Debug("failed to connect to default backend", "error", err)
			return
		}
		defer backend.Close()
		s.forwardToSite(clientConn, backend, nil, logger)
		return
	}

	if siteConn != nil {
		s.forwardToSite(clientConn, siteConn, nil, logger)
		return
	}

	logger.Debug("no fallback, closing connection naturally")
}

// resolveDestination 将 SNI 解析为 IP 地址。
func (s *Server) resolveDestination(sni string) (string, error) {
	addrs, err := net.LookupHost(sni)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", sni, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses for %s", sni)
	}
	return addrs[0], nil
}

// extractSNI 从 ClientHello 消息中提取服务器名称指示（SNI）。
func extractSNI(handshakeMsg []byte) string {
	if len(handshakeMsg) < 4 {
		return ""
	}

	offset := 4
	if len(handshakeMsg) < offset+34 {
		return ""
	}
	offset += 34

	if offset >= len(handshakeMsg) {
		return ""
	}
	sessionIDLen := int(handshakeMsg[offset])
	offset++
	if len(handshakeMsg) < offset+sessionIDLen {
		return ""
	}
	offset += sessionIDLen

	if offset+2 > len(handshakeMsg) {
		return ""
	}
	cipherSuitesLen := int(handshakeMsg[offset])<<8 | int(handshakeMsg[offset+1])
	offset += 2
	if len(handshakeMsg) < offset+cipherSuitesLen {
		return ""
	}
	offset += cipherSuitesLen

	if offset >= len(handshakeMsg) {
		return ""
	}
	compressionLen := int(handshakeMsg[offset])
	offset++
	if len(handshakeMsg) < offset+compressionLen {
		return ""
	}
	offset += compressionLen

	if offset+2 > len(handshakeMsg) {
		return ""
	}
	extensionsLen := int(handshakeMsg[offset])<<8 | int(handshakeMsg[offset+1])
	offset += 2
	if len(handshakeMsg) < offset+extensionsLen {
		return ""
	}

	extensionsEnd := offset + extensionsLen
	for offset+4 <= extensionsEnd {
		extType := int(handshakeMsg[offset])<<8 | int(handshakeMsg[offset+1])
		extLen := int(handshakeMsg[offset+2])<<8 | int(handshakeMsg[offset+3])
		offset += 4

		if extType == 0x0000 {
			if offset+2 <= extensionsEnd {
				sniOffset := offset + 2
				if sniOffset+3 <= extensionsEnd {
					nameType := handshakeMsg[sniOffset]
					if nameType == 0 {
						nameLen := int(handshakeMsg[sniOffset+1])<<8 | int(handshakeMsg[sniOffset+2])
						nameStart := sniOffset + 3
						if nameStart+nameLen <= extensionsEnd {
							return string(handshakeMsg[nameStart : nameStart+nameLen])
						}
					}
				}
			}
		}

		offset += extLen
	}

	return ""
}

// findChimneyRecord 扫描拼接的 TLS 记录缓冲区，寻找有效的
// ChimneyRecord。它遍历每个 TLS 记录，对于每个 0x17
// （application_data）记录，创建一个新的编解码器并尝试解密。
// 第一个成功解密的记录作为 chimneyRecord 返回。
// 它之前的所有记录（包括非 Chimney 的 0x17 记录，如 uTLS
// 握手后的记录）作为 preludeRecords 返回，用于转发到真实站点。
func findChimneyRecord(data []byte, deriver *keyderiv.Deriver, serverRandom, clientRandom []byte, logger *slog.Logger) (chimneyRecord, preludeRecords []byte) {
	scanned := 0
	for len(data) >= record.RecordHeaderLen {
		recType := data[0]
		recLen := int(data[3])<<8 | int(data[4])
		total := record.RecordHeaderLen + recLen
		if len(data) < total {
			break
		}

		if recType == record.RecordTypeApplicationData {
			sendKey, recvKey, err := deriver.DeriveDirectionalKeys(serverRandom, clientRandom)
			if err != nil {
				data = data[total:]
				scanned++
				continue
			}
			sendNonceBase, _ := deriver.DeriveNonceBase(serverRandom, clientRandom)
			recvNonceBase, _ := deriver.DeriveNonceBase(clientRandom, serverRandom)
			testCodec, err := record.NewCodecWithDirectionalKeys(recvKey, recvNonceBase, sendKey, sendNonceBase)
			if err != nil {
				data = data[total:]
				scanned++
				continue
			}

			recordData := make([]byte, total)
			copy(recordData, data[:total])
			_, decErr := testCodec.DecodeRecord(recordData)
			if decErr == nil {
				logger.Debug("found valid ChimneyRecord", "offset", len(preludeRecords), "len", total)
				return data[:total], preludeRecords
			}
		}

		preludeRecords = append(preludeRecords, data[:total]...)
		data = data[total:]
		scanned++
	}
	if scanned > 0 {
		logger.Debug("no ChimneyRecord found", "scanned", scanned, "total_bytes", len(preludeRecords))
	}
	return nil, preludeRecords
}

// NewDeriverFromHexOrRaw 创建一个能同时处理十六进制和原始 PSK 的派生器。
func NewDeriverFromHexOrRaw(psk string) *keyderiv.Deriver {
	if d, err := keyderiv.NewDeriverFromHex(psk); err == nil {
		return d
	}
	return keyderiv.NewDeriver([]byte(psk))
}
