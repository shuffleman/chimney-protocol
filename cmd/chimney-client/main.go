// cmd/chimney-client 是 Chimney 客户端。
//
// 客户端连接到 Chimney 中继，通过中继与白名单站点执行真实的 TLS 握手，
// 在第一个 application_data 记录中嵌入认证标签，
// 然后建立 H2 隧道。
//
// 用法：
//
//	chimney-client -relay relay.example.com:443 -sni real-site.com -dest final-destination.com:443
//
// 客户端使用 uTLS 模拟真实浏览器的 TLS 指纹。
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/shuffleman/chimney-protocol/internal/auth"
	cfgpkg "github.com/shuffleman/chimney-protocol/internal/config"
	"github.com/shuffleman/chimney-protocol/internal/dilution"
	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/keyderiv"
	"github.com/shuffleman/chimney-protocol/internal/profile"
	"github.com/shuffleman/chimney-protocol/internal/record"
)

const (
	// DefaultRelayTimeout 是中继连接的超时时间。
	DefaultRelayTimeout = 10 * time.Second

	// DefaultHandshakeTimeout 是 TLS 握手的超时时间。
	DefaultHandshakeTimeout = 10 * time.Second

	// socksHandshakeTimeout 限制未经认证的本地 SOCKS5 握手的超时。
	socksHandshakeTimeout = 10 * time.Second

	// tunnelIdleTimeout 限制 dispatch 在阻塞流上等待的时间，
	// 超过后将声明隧道不健康。
	tunnelIdleTimeout = 30 * time.Second

	// maxTunnelDataChunk 为 Chimney 隧道命令前缀保留一个字节，
	// 使每个 H2 DATA 帧携带自己的 0x02 DATA 命令。
	maxTunnelDataChunk = 16*1024 - 1
)

func main() {
	var (
		configPath     = flag.String("config", "", "Path to client configuration file")
		relayAddr      = flag.String("relay", "", "Relay address (host:port)")
		sni            = flag.String("sni", "", "SNI to use (whitelisted site)")
		destAddr       = flag.String("dest", "", "Final destination (host:port)")
		pskHex         = flag.String("psk", "", "Pre-shared key (hex-encoded)")
		tagLen         = flag.Int("tag-len", auth.DefaultTagLen, "Auth tag length")
		listenAddr     = flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
		fingerprintStr = flag.String("fingerprint", "chrome", "TLS fingerprint(s) to use (comma-separated for rotation)")
		profileFile    = flag.String("profile", "", "Traffic profile JSON for padding (enables padding stream)")
		paddingTarget  = flag.Int("padding-target", 0, "Override padding target size (0 = use profile distribution)")
		dilutionFile   = flag.String("dilution", "", "Pre-recorded content blocks JSON for dilution stream")
		userID         = flag.String("user-id", "", "User identifier (UUID) for multi-user relay (default: \"default\")")
	)
	flag.Parse()

	explicitFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	if *configPath != "" {
		cfg, err := cfgpkg.LoadClientConfig(*configPath)
		if err != nil {
			logger.Error("failed to load client configuration", "path", *configPath, "error", err)
			os.Exit(1)
		}
		applyClientConfig(cfg, explicitFlags, relayAddr, sni, destAddr, pskHex, tagLen, listenAddr, fingerprintStr, userID)
	}

	if *relayAddr == "" || *sni == "" || *destAddr == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s [-config client.yaml] -relay <host:port> -sni <site> -dest <host:port> [-psk <hex> | -user-id <uuid>]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 创建客户端
	fingerprints := strings.Split(*fingerprintStr, ",")
	fpRotator, err := NewFingerprintRotator(fingerprints)
	if err != nil {
		logger.Error("invalid fingerprint", "error", err)
		os.Exit(1)
	}
	logger.Info("fingerprint rotation configured", "fingerprints", FingerprintNames(fpRotator))

	// 加载流量配置文件以进行填充（可选）
	var trafficProfile *profile.Model
	if *profileFile != "" {
		trafficProfile, err = profile.LoadModelFromFile(*profileFile)
		if err != nil {
			logger.Error("failed to load profile", "error", err)
			os.Exit(1)
		}
		logger.Info("traffic profile loaded",
			"site", trafficProfile.SiteName,
			"padding_mode", "enabled",
		)
	}

	// 加载稀释内容块（可选）
	var dilutionProv *dilution.Provider
	if *dilutionFile != "" {
		dilutionProv, err = dilution.LoadProviderFromFile(*dilutionFile)
		if err != nil {
			logger.Error("failed to load dilution blocks", "error", err)
			os.Exit(1)
		}
		logger.Info("dilution content blocks loaded",
			"blocks", dilutionProv.Len(),
			"dilution_mode", "enabled",
		)
	}

	uid := *userID
	psk := *pskHex
	if psk == "" {
		if uid == "" {
			logger.Error("missing credentials", "error", "provide -psk or -user-id")
			os.Exit(1)
		}
		psk = hex.EncodeToString(auth.DerivePSKFromID(uid))
	} else if uid == "" {
		uid = "default"
	}

	client := &Client{
		RelayAddr:        *relayAddr,
		SNI:              *sni,
		DestAddr:         *destAddr,
		PSKHex:           psk,
		UserID:           uid,
		TagLen:           *tagLen,
		ListenAddr:       *listenAddr,
		Fingerprints:     fpRotator,
		Profile:          trafficProfile,
		PaddingTarget:    *paddingTarget,
		DilutionProvider: dilutionProv,
		Logger:           logger,
	}

	if err := client.Run(); err != nil {
		logger.Error("client failed", "error", err)
		os.Exit(1)
	}
}

func applyClientConfig(
	cfg *cfgpkg.ClientConfig,
	explicitFlags map[string]bool,
	relayAddr *string,
	sni *string,
	destAddr *string,
	pskHex *string,
	tagLen *int,
	listenAddr *string,
	fingerprintStr *string,
	userID *string,
) {
	if !explicitFlags["relay"] {
		*relayAddr = cfg.RelayAddr
	}
	if !explicitFlags["sni"] {
		*sni = cfg.SNI
	}
	if !explicitFlags["dest"] {
		*destAddr = cfg.DestAddr
	}
	if !explicitFlags["psk"] {
		*pskHex = cfg.PSK
	}
	if !explicitFlags["tag-len"] {
		*tagLen = cfg.TagLen
	}
	if !explicitFlags["listen"] {
		*listenAddr = cfg.ListenAddr
	}
	if !explicitFlags["fingerprint"] {
		*fingerprintStr = cfg.UTlsFingerprint
	}
	if !explicitFlags["user-id"] {
		*userID = cfg.UserID
	}
}

// Client 是 Chimney 客户端。
type Client struct {
	RelayAddr        string
	SNI              string
	DestAddr         string
	PSKHex           string
	UserID           string
	TagLen           int
	ListenAddr       string
	Fingerprints     *FingerprintRotator
	Profile          *profile.Model
	PaddingTarget    int
	DilutionProvider *dilution.Provider
	Logger           *slog.Logger
}

// Run 启动客户端。
func (c *Client) Run() error {
	manager, err := c.newTunnelManager()
	if err != nil {
		return err
	}
	defer manager.Close()

	// 启动本地 SOCKS5 代理，通过重连隧道转发流量。
	return c.runSOCKS5(manager)
}

// establishTunnel 建立到中继的 Chimney 隧道。
//
// 协议流程（修订版，用于交换后认证）：
//  1. TCP 连接到中继
//  2. TLS 握手，SNI=白名单站点（使用 uTLS Chrome 指纹）
//  3. 从握手中提取 ServerRandom 和 ClientRandom
//  4. 发送一个虚拟的第一个 application_data 记录（TLS 加密）作为启发式
//     触发中继——包含最小的 H2 类填充
//  5. 计算认证标签 = HMAC(K_auth, ServerRandom || ClientRandom)
//  6. 从 PSK + 两个随机数派生 K_sess
//  7. 切换到 ChimneyRecord 层（使用 K_sess 的 AEAD）
//  8. 发送 H2 前言 + SETTINGS 作为 ChimneyRecords
//  9. 完成 H2 握手（SETTINGS + ACK 交换）
//
// 10. 在流 1 上发送认证标签作为第一个 DATA 帧
// 11. 中继验证交换后状态；隧道准备就绪
func (c *Client) establishTunnel() (net.Conn, error) {
	// 第 1 步：连接到中继
	conn, err := net.DialTimeout("tcp", c.RelayAddr, DefaultRelayTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to relay: %w", err)
	}

	// 第 2 步：使用 SNI=白名单站点执行 TLS 握手
	tlsConfig := &utls.Config{
		ServerName:         c.SNI,
		InsecureSkipVerify: true,
		NextProtos:         defaultTLSNextProtos(),
	}

	fpID := c.Fingerprints.Next()
	c.Logger.Debug("using TLS fingerprint", "client", fpID.Client, "version", fpID.Version)

	uConn := utls.UClient(conn, tlsConfig, fpID)
	uConn.SetSNI(c.SNI)

	if err := uConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	if negotiated := uConn.ConnectionState().NegotiatedProtocol; negotiated != "h2" {
		uConn.Close()
		return nil, fmt.Errorf("TLS ALPN negotiated %q, want h2", negotiated)
	}

	// 第 3 步：提取握手状态
	serverRandom := uConn.HandshakeState.ServerHello.Random
	clientRandom := uConn.HandshakeState.Hello.Random

	if len(serverRandom) != 32 || len(clientRandom) != 32 {
		uConn.Close()
		return nil, fmt.Errorf("invalid random length")
	}

	c.Logger.Debug("TLS handshake complete",
		"server_random", hex.EncodeToString(serverRandom),
		"client_random", hex.EncodeToString(clientRandom),
	)

	// 第 4 步：握手后立即派生密钥。
	// 中继在 TLS 记录层拦截第一个 application_data 记录（0x17）——
	// 无需宽限期或虚拟记录。
	deriver, err := keyderiv.NewDeriverFromHex(c.PSKHex)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("create deriver: %w", err)
	}

	// 计算认证标签 = HMAC(K_auth, ServerRandom || ClientRandom)
	tag, err := deriver.AuthTag(serverRandom, clientRandom, c.TagLen)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("compute auth tag: %w", err)
	}

	// 计算多用户认证的密钥提示。
	keyHint := keyderiv.ComputeKeyHint(c.UserID)

	// 派生客户端方向的定向密钥
	sendKey, recvKey, err := deriver.DeriveDirectionalKeys(serverRandom, clientRandom)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("derive directional keys: %w", err)
	}
	sendNonceBase, err := deriver.DeriveNonceBase(serverRandom, clientRandom)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("derive send nonce base: %w", err)
	}
	recvNonceBase, err := deriver.DeriveNonceBase(clientRandom, serverRandom)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("derive recv nonce base: %w", err)
	}

	c.Logger.Debug("directional keys derived (CLIENT)",
		"sendKey", hex.EncodeToString(sendKey[:4]),
		"recvKey", hex.EncodeToString(recvKey[:4]),
		"sendNonce", hex.EncodeToString(sendNonceBase),
		"recvNonce", hex.EncodeToString(recvNonceBase),
	)

	codec, err := record.NewCodecWithDirectionalKeys(sendKey, sendNonceBase, recvKey, recvNonceBase)
	if err != nil {
		// 回退到双向模式
		kSess, _ := deriver.DeriveSessionKey(serverRandom, clientRandom)
		nonceBase, _ := deriver.DeriveNonceBase(serverRandom, clientRandom)
		codec, err = record.NewCodec(kSess, nonceBase)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("create record codec: %w", err)
		}
	}

	// 第 6 步：切换到 ChimneyRecord 前，从 TCP 缓冲区排干陈旧字节。
	// 中继在握手期间转发了所有服务器→客户端的数据，包括
	// 任何握手后记录（例如 NewSessionTicket）。uTLS 消费了它
	// 需要的内容，但操作系统缓冲区中的剩余数据会混淆 RecordReader。
	rawConn := uConn.GetUnderlyingConn()
	rawConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	drainBuf := make([]byte, 8192)
	drained := 0
	for {
		n, err := rawConn.Read(drainBuf)
		drained += n
		if err != nil {
			break
		}
	}
	rawConn.SetReadDeadline(time.Time{})
	c.Logger.Debug("drained stale TCP bytes", "bytes", drained)

	// 第 7 步：使用 ChimneyRecord 层包装连接（使用原始 TCP）
	recReader := record.NewRecordReader(rawConn, codec)
	recWriter := record.NewRecordWriter(rawConn, codec)

	c.Logger.Debug("codec created, sending H2 preface as ChimneyRecord")

	// 第 7 步：发送 H2 前言 + SETTINGS 作为 ChimneyRecords
	settings := h2engine.DefaultSettings()
	h2Opening := h2engine.GenerateClientOpeningSequence(settings)
	c.Logger.Debug("sending H2 preface as ChimneyRecord",
		"h2_opening_len", len(h2Opening),
		"sealer_key_hex", hex.EncodeToString(sendKey),
		"sealer_nonce_hex", hex.EncodeToString(sendNonceBase),
	)
	if err := recWriter.WriteRecord(h2Opening); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("send H2 preface: %w", err)
	}

	// 创建 H2 引擎
	h2Eng := h2engine.NewEngine(settings, codec)
	h2Eng.SetRecordIO(recReader, recWriter)

	// 第 8 步：完成 H2 握手
	if err := c.completeH2Handshake(h2Eng, recWriter); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("H2 handshake: %w", err)
	}

	// 第 9 步：发送带密钥提示前缀的认证标签。
	// 扩展格式：[key_hint (4 字节)] [tag (tagLen 字节)]
	authStreamID := h2Eng.OpenStream()
	authPayload := make([]byte, 4+len(tag))
	copy(authPayload, keyHint[:])
	copy(authPayload[4:], tag)
	tagFrame := h2engine.DataFrame(authStreamID, 0, authPayload)
	if err := recWriter.WriteRecord(tagFrame); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("send auth tag frame: %w", err)
	}

	c.Logger.Debug("sent post-swap auth tag",
		"hint", hex.EncodeToString(keyHint[:]),
		"tag", hex.EncodeToString(tag),
		"stream", authStreamID,
	)

	// 第 10 步：等待中继的认证确认（空 DATA 帧或 SETTINGS ACK）
	// 中继发送新的 SETTINGS 帧或直接继续——如果我们到达这里
	// 没有错误，则表示隧道已建立

	c.Logger.Info("Chimney tunnel established")

	return newTunnelConn(rawConn, h2Eng, recReader, recWriter, c.Profile, c.PaddingTarget, c.DilutionProvider), nil
}

// completeH2Handshake 在交换后完成 H2 握手。
func (c *Client) completeH2Handshake(h2Eng *h2engine.Engine, recWriter *record.RecordWriter) error {
	// 作为客户端，我们已经发送了前言 + SETTINGS
	// 现在我们需要：
	// 1. 接收服务器 SETTINGS
	// 2. 发送 SETTINGS ACK
	// 3. 接收服务器 SETTINGS ACK

	// 读取服务器 SETTINGS 帧
	fh, _, err := h2Eng.ReadFrame()
	if err != nil {
		return fmt.Errorf("read server SETTINGS: %w", err)
	}
	if fh.Type != h2engine.FrameSettings {
		return fmt.Errorf("expected SETTINGS, got frame type 0x%x", fh.Type)
	}

	// 发送 SETTINGS ACK 帧
	ackFrame := h2engine.DefaultSettings().EncodeSettings(true)
	if err := recWriter.WriteRecord(ackFrame); err != nil {
		return fmt.Errorf("send SETTINGS ACK: %w", err)
	}

	// 读取服务器 SETTINGS ACK 帧
	fh, _, err = h2Eng.ReadFrame()
	if err != nil {
		return fmt.Errorf("read SETTINGS ACK: %w", err)
	}
	if fh.Type != h2engine.FrameSettings || fh.Flags&h2engine.FlagAck == 0 {
		return fmt.Errorf("expected SETTINGS ACK, got frame type 0x%x flags 0x%x", fh.Type, fh.Flags)
	}

	return nil
}

type tunnelManager struct {
	client *Client

	mu     sync.Mutex
	tunnel *tunnelConn
}

func (c *Client) newTunnelManager() (*tunnelManager, error) {
	m := &tunnelManager{client: c}
	if _, err := m.getTunnel(); err != nil {
		return nil, fmt.Errorf("establish tunnel: %w", err)
	}
	return m, nil
}

func (m *tunnelManager) getTunnel() (*tunnelConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.tunnel != nil && m.tunnel.isAlive() {
		return m.tunnel, nil
	}

	if m.tunnel != nil {
		m.client.Logger.Info("tunnel is down, reconnecting", "error", m.tunnel.LastError())
		_ = m.tunnel.Close()
	}

	tunnel, err := m.client.establishTunnel()
	if err != nil {
		return nil, err
	}
	tc, ok := tunnel.(*tunnelConn)
	if !ok {
		_ = tunnel.Close()
		return nil, fmt.Errorf("unexpected tunnel type %T", tunnel)
	}

	m.tunnel = tc
	m.client.Logger.Info("tunnel established",
		"relay", m.client.RelayAddr,
		"sni", m.client.SNI,
		"dest", m.client.DestAddr,
	)
	return tc, nil
}

func (m *tunnelManager) reconnect() (*tunnelConn, error) {
	m.mu.Lock()
	if m.tunnel != nil {
		_ = m.tunnel.Close()
		m.tunnel = nil
	}
	m.mu.Unlock()
	return m.getTunnel()
}

func (m *tunnelManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tunnel == nil {
		return nil
	}
	return m.tunnel.Close()
}

// runSOCKS5 运行本地 SOCKS5 代理，通过隧道转发流量。
func (c *Client) runSOCKS5(manager *tunnelManager) error {
	listener, err := net.Listen("tcp", c.ListenAddr)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen: %w", err)
	}
	defer listener.Close()

	c.Logger.Info("SOCKS5 proxy listening", "addr", c.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			c.Logger.Error("SOCKS5 accept failed", "error", err)
			continue
		}

		go c.handleSOCKS5Conn(conn, manager)
	}
}

// handleSOCKS5Conn 处理单个 SOCKS5 连接。
func (c *Client) handleSOCKS5Conn(clientConn net.Conn, manager *tunnelManager) {
	defer clientConn.Close()

	if err := clientConn.SetDeadline(time.Now().Add(socksHandshakeTimeout)); err != nil {
		c.Logger.Debug("failed to set SOCKS5 deadline", "error", err)
		return
	}

	// SOCKS5 握手
	if err := c.socks5Handshake(clientConn); err != nil {
		c.Logger.Debug("SOCKS5 handshake failed", "error", err)
		return
	}

	// 读取连接请求
	targetAddr, err := c.socks5ReadRequest(clientConn)
	if err != nil {
		c.Logger.Debug("SOCKS5 request failed", "error", err)
		return
	}
	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		c.Logger.Debug("failed to clear SOCKS5 deadline", "error", err)
		return
	}

	c.Logger.Debug("SOCKS5 connect", "target", targetAddr)

	// 通过中继打开到目标的隧道流
	tc, err := manager.getTunnel()
	if err != nil {
		c.Logger.Debug("tunnel unavailable", "error", err)
		c.socks5SendReply(clientConn, 0x01) // General SOCKS server failure
		return
	}
	stream, err := tc.openStream(targetAddr)
	if err != nil {
		c.Logger.Debug("tunnel stream open failed, retrying with fresh tunnel", "error", err)
		if tc, err = manager.reconnect(); err == nil {
			stream, err = tc.openStream(targetAddr)
		}
		if err != nil {
			c.Logger.Debug("tunnel stream open retry failed", "error", err)
			c.socks5SendReply(clientConn, 0x01) // General SOCKS server failure
			return
		}
	}
	// 发送 SOCKS5 成功响应
	if err := c.socks5SendReply(clientConn, 0x00); err != nil {
		stream.Close()
		return
	}

	// SOCKS5 客户端和隧道流之间的双向中继
	relayBidirectional(clientConn, stream)
}

func relayBidirectional(clientConn net.Conn, stream io.ReadWriteCloser) {
	var wg sync.WaitGroup
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			stream.Close()
			clientConn.Close()
		})
	}

	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(stream, clientConn)
		closeBoth()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, stream)
		closeBoth()
	}()

	wg.Wait()
}

// socks5Handshake 执行 SOCKS5 认证握手。
func (c *Client) socks5Handshake(conn net.Conn) error {
	// 读取认证方法
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// 回复无需认证（0x00）
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}

	return nil
}

// socks5ReadRequest 读取 SOCKS5 连接请求。
func (c *Client) socks5ReadRequest(conn net.Conn) (string, error) {
	// 读取固定头部
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != 0x05 || header[1] != 0x01 { // 必须是 CONNECT
		return "", fmt.Errorf("unsupported SOCKS5 command: %d", header[1])
	}

	// 读取地址
	var addr string
	switch header[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return "", err
		}
		addr = fmt.Sprintf("%s:%d", net.IP(ip), int(port[0])<<8|int(port[1]))

	case 0x03: // 域名
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return "", err
		}
		addr = fmt.Sprintf("%s:%d", string(domain), int(port[0])<<8|int(port[1]))

	default:
		return "", fmt.Errorf("unsupported address type: %d", header[3])
	}

	return addr, nil
}

// socks5SendReply 发送 SOCKS5 响应。
func (c *Client) socks5SendReply(conn net.Conn, code byte) error {
	reply := []byte{0x05, code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(reply)
	return err
}

// streamFrame 是为特定 H2 流接收的帧。
type streamFrame struct {
	fh      *h2engine.FrameHeader
	payload []byte
}

// tunnelConn 使用 H2 流多路复用包装原始 TCP 连接。
type tunnelConn struct {
	net.Conn
	h2Engine      *h2engine.Engine
	recReader     *record.RecordReader
	recWriter     *record.RecordWriter
	profile       *profile.Model
	paddingTarget int
	dilution      *dilution.Provider

	mu      sync.Mutex
	streams map[uint32]chan *streamFrame
	quit    chan struct{}
	dead    chan struct{}
	lastErr error

	closeOnce sync.Once
	deadOnce  sync.Once
}

// newTunnelConn 创建 tunnelConn 并启动其帧分发器。
func newTunnelConn(rawConn net.Conn, h2Eng *h2engine.Engine, recReader *record.RecordReader, recWriter *record.RecordWriter, prof *profile.Model, paddingTarget int, dilutionProv *dilution.Provider) *tunnelConn {
	tc := &tunnelConn{
		Conn:          rawConn,
		h2Engine:      h2Eng,
		recReader:     recReader,
		recWriter:     recWriter,
		profile:       prof,
		paddingTarget: paddingTarget,
		dilution:      dilutionProv,
		streams:       make(map[uint32]chan *streamFrame),
		quit:          make(chan struct{}),
		dead:          make(chan struct{}),
	}
	go tc.dispatchFrames()
	if dilutionProv != nil && prof != nil {
		go tc.dilutionLoop()
	}
	return tc
}

func (tc *tunnelConn) isAlive() bool {
	select {
	case <-tc.dead:
		return false
	default:
		return true
	}
}

func (tc *tunnelConn) LastError() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.lastErr
}

func (tc *tunnelConn) Close() error {
	var err error
	tc.closeOnce.Do(func() {
		close(tc.quit)
		tc.recWriter.Close()
		err = tc.Conn.Close()
		tc.markDead(err)
	})
	return err
}

func (tc *tunnelConn) markDead(err error) {
	tc.mu.Lock()
	if err != nil {
		tc.lastErr = err
	}
	tc.streams = make(map[uint32]chan *streamFrame)
	tc.mu.Unlock()

	tc.deadOnce.Do(func() {
		close(tc.dead)
	})
}

// dispatchFrames 从 H2 引擎读取帧并路由到每个流的通道。
func (tc *tunnelConn) dispatchFrames() {
	tc.Conn.SetReadDeadline(time.Now().Add(tunnelIdleTimeout))

	for {
		select {
		case <-tc.quit:
			return
		default:
		}
		fh, payload, err := tc.h2Engine.ReadFrame()
		if err != nil {
			tc.markDead(err)
			return
		}
		tc.Conn.SetReadDeadline(time.Now().Add(tunnelIdleTimeout))

		if !tc.deliverFrame(fh, payload) {
			return
		}
	}
}

func (tc *tunnelConn) deliverFrame(fh *h2engine.FrameHeader, payload []byte) bool {
	tc.mu.Lock()
	ch, ok := tc.streams[fh.StreamID]
	tc.mu.Unlock()
	if !ok {
		return true
	}

	sf := &streamFrame{fh, payload}
	select {
	case ch <- sf:
		return true
	default:
		select {
		case ch <- sf:
			return true
		case <-tc.quit:
			return false
		case <-time.After(tunnelIdleTimeout):
			err := fmt.Errorf("tunnel stream %d blocked for %s", fh.StreamID, tunnelIdleTimeout)
			tc.Conn.Close()
			tc.markDead(err)
			return false
		}
	}
}

// dilutionLoop 定期发送携带真实 HTTP 内容的稀释记录
// 以保持 DPI 下的语义不可区分性。它使用流量
// 配置文件的延迟分布来控制时序，记录大小分布来控制大小。
func (tc *tunnelConn) dilutionLoop() {
	interval := tc.profile.RecordDelay()
	if interval <= 0 {
		interval = 2 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-tc.quit:
			return
		case <-ticker.C:
			targetSize := tc.profile.RecordSize()

			content := tc.dilution.GetBlock(targetSize)
			if content == nil {
				continue
			}

			if err := tc.h2Engine.WriteDilutionRecord(content, targetSize); err != nil {
				return
			}

			// 重新采样间隔以产生自然抖动
			nextInterval := tc.profile.RecordDelay()
			if nextInterval > 0 {
				ticker.Reset(nextInterval)
			}
		}
	}
}

// openStream 打开一个新的 H2 流并向中继发送 CONNECT 命令。
func (tc *tunnelConn) openStream(dest string) (*tunnelStream, error) {
	streamID := tc.h2Engine.OpenStream()
	ch := make(chan *streamFrame, 16)

	tc.mu.Lock()
	tc.streams[streamID] = ch
	tc.mu.Unlock()

	// 发送 CONNECT 命令
	connectCmd := make([]byte, 1+len(dest))
	connectCmd[0] = 0x01
	copy(connectCmd[1:], dest)
	if err := tc.h2Engine.WriteData(streamID, connectCmd, false); err != nil {
		tc.mu.Lock()
		delete(tc.streams, streamID)
		tc.mu.Unlock()
		return nil, err
	}

	// 等待 CONNECT_OK
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case sf, ok := <-ch:
			if !ok {
				return nil, fmt.Errorf("tunnel closed")
			}
			if sf.fh.Type == h2engine.FrameData && len(sf.payload) > 0 {
				switch sf.payload[0] {
				case 0x01: // CONNECT_OK
					return &tunnelStream{
						tc:       tc,
						streamID: streamID,
						ch:       ch,
					}, nil
				default:
					tc.mu.Lock()
					delete(tc.streams, streamID)
					tc.mu.Unlock()
					return nil, fmt.Errorf("backend connect failed: code 0x%02x", sf.payload[0])
				}
			}
		case <-tc.dead:
			return nil, fmt.Errorf("tunnel closed")
		case <-tc.quit:
			return nil, fmt.Errorf("tunnel closed")
		case <-timeout.C:
			tc.mu.Lock()
			delete(tc.streams, streamID)
			tc.mu.Unlock()
			return nil, fmt.Errorf("CONNECT timeout")
		}
	}
}

// tunnelStream 是隧道内的单个 H2 流。
type tunnelStream struct {
	tc       *tunnelConn
	streamID uint32
	ch       chan *streamFrame
	readBuf  []byte
}

// Read 从流中读取数据，剥离 0x02 DATA 前缀。
func (ts *tunnelStream) Read(p []byte) (int, error) {
	if len(ts.readBuf) > 0 {
		n := copy(p, ts.readBuf)
		ts.readBuf = ts.readBuf[n:]
		if len(ts.readBuf) == 0 {
			ts.readBuf = nil
		}
		return n, nil
	}

	var sf *streamFrame
	select {
	case got, ok := <-ts.ch:
		if !ok {
			return 0, io.EOF
		}
		sf = got
	case <-ts.tc.dead:
		return 0, io.EOF
	case <-ts.tc.quit:
		return 0, io.EOF
	}

	if sf.fh.Type == h2engine.FrameData && len(sf.payload) > 0 {
		switch sf.payload[0] {
		case 0x02: // DATA
			n := copy(p, sf.payload[1:])
			if n < len(sf.payload)-1 {
				ts.readBuf = append(ts.readBuf[:0], sf.payload[1+n:]...)
			}
			return n, nil
		case 0x03: // CLOSE
			return 0, io.EOF
		}
	}
	return 0, nil
}

// Write 将数据写入流，加上 0x02 DATA 命令前缀。
// 如果配置了流量配置文件，记录会被填充以匹配
// 目标大小分布。
func (ts *tunnelStream) Write(p []byte) (int, error) {
	var targetSize uint16
	if ts.tc.profile != nil {
		if ts.tc.paddingTarget > 0 {
			targetSize = uint16(ts.tc.paddingTarget)
		} else {
			targetSize = ts.tc.profile.RecordSize()
		}
	}

	for offset := 0; offset < len(p); {
		chunkSize := len(p) - offset
		if chunkSize > maxTunnelDataChunk {
			chunkSize = maxTunnelDataChunk
		}
		data := make([]byte, 1+chunkSize)
		data[0] = 0x02
		copy(data[1:], p[offset:offset+chunkSize])

		if targetSize > 0 {
			if err := ts.tc.h2Engine.WritePaddedRecord(ts.streamID, data, targetSize, false); err != nil {
				return offset, err
			}
		} else {
			if err := ts.tc.h2Engine.WriteData(ts.streamID, data, false); err != nil {
				return offset, err
			}
		}
		offset += chunkSize
	}
	return len(p), nil
}

// Close 发送 CLOSE 命令并注销流。
func (ts *tunnelStream) Close() error {
	ts.tc.h2Engine.WriteData(ts.streamID, []byte{0x03}, false)
	ts.tc.mu.Lock()
	delete(ts.tc.streams, ts.streamID)
	ts.tc.mu.Unlock()
	ts.readBuf = nil
	for {
		select {
		case <-ts.ch:
		default:
			return nil
		}
	}
}

func defaultTLSNextProtos() []string {
	return []string{"h2", "http/1.1"}
}
