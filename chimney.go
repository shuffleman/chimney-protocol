// Package chimney exports a Dialer that establishes connections through a
// Chimney relay. It is designed to be imported by sing-box, Xray-core, or
// any Go project that needs a net.Conn over the Chimney protocol.
//
// Usage:
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
//	// conn is a net.Conn — use like any TCP connection.
//
// The Dialer maintains a pool of H2 connections to the relay. Each connection
// has its own TCP socket and frame-dispatch goroutine, so higher PoolSize
// values increase throughput for high-concurrency workloads. PoolSize defaults
// to 4; set to 1 for single-connection mode (lower resource usage).
package chimney

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
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
)

const (
	// DefaultConnectTimeout is the default timeout for establishing the tunnel.
	DefaultConnectTimeout = 10 * time.Second

	// DefaultHandshakeTimeout is the default timeout for TLS + H2 handshake.
	DefaultHandshakeTimeout = 10 * time.Second

	// DefaultPoolSize is the default number of parallel H2 connections.
	DefaultPoolSize = 4
)

// Config holds all parameters for establishing a Chimney tunnel.
// Only RelayAddr, SNI, and PSK are required; all other fields have defaults.
type Config struct {
	// RelayAddr is the relay server address (host:port). Required.
	RelayAddr string

	// SNI is the TLS Server Name Indication — must be a whitelisted site. Required.
	SNI string

	// PSK is the pre-shared key (64 hex chars = 256 bits). Required.
	PSK string

	// UserID is the user identifier (e.g. UUID) for multi-user relay deployments.
	// It is hashed to a 4-byte key hint sent alongside the auth tag.
	// If empty, defaults to "default" (single-user mode).
	UserID string

	// TagLen is the auth tag length in bytes (default: 16).
	TagLen int

	// Fingerprint is the uTLS ClientHello fingerprint name (default: "chrome").
	// Available: chrome, firefox, safari, ios, edge, android, 360, qq,
	// randomized, golang — with optional -version (e.g. "chrome-120").
	Fingerprint string

	// ProfilePath is an optional traffic profile JSON for padding.
	// Empty string disables padding.
	ProfilePath string

	// PaddingTarget overrides the padding record size. 0 = use profile distribution.
	PaddingTarget int

	// DilutionPath is an optional content blocks JSON for the dilution stream.
	// Empty string disables dilution.
	DilutionPath string

	// ConnectTimeout is the TCP connect timeout (default: 10s).
	ConnectTimeout time.Duration

	// HandshakeTimeout is the TLS + H2 handshake timeout (default: 10s).
	HandshakeTimeout time.Duration

	// PoolSize is the number of parallel H2 connections to the relay (default: 4).
	// Higher values increase throughput under high concurrency by parallelising
	// frame dispatch across multiple TCP sockets. Set to 1 for single-connection
	// mode (lowest resource usage, sufficient for low concurrency).
	PoolSize int
}

// tunnel is a single H2 connection to the relay. The Dialer maintains a pool
// of these to parallelise frame dispatch under high concurrency.
type tunnel struct {
	rawConn   net.Conn
	h2Eng     *h2engine.Engine
	recReader *record.RecordReader
	recWriter *record.RecordWriter
	prof      *profile.Model
	padTarget int
	dilution  *dilution.Provider

	mu      sync.Mutex
	streams map[uint32]chan *streamFrame
	quit    chan struct{}
	dead    chan struct{}
	closed  bool
}

// A Dialer maintains a pool of H2 connections to a Chimney relay.
// Multiple goroutines may invoke DialContext concurrently; calls are
// distributed across the pool connections round-robin.
type Dialer struct {
	config Config
	pool   []*tunnel
	next   atomic.Uint32
	mu     sync.Mutex
	closed bool

	prof     *profile.Model
	dilution *dilution.Provider
}

// streamFrame is a frame received for a specific H2 stream.
type streamFrame struct {
	fh      *h2engine.FrameHeader
	payload []byte
}

// streamConn wraps a single H2 stream as a net.Conn.
type streamConn struct {
	t        *tunnel
	streamID uint32
	ch       chan *streamFrame

	readBuf []byte // leftover data from partial read of an H2 frame payload

	readDeadline  time.Time
	writeDeadline time.Time
}

// addr is a trivial net.Addr implementation.
type addr struct{ network, str string }

func (a addr) Network() string { return a.network }
func (a addr) String() string  { return a.str }

// Read reads data from the stream, stripping the 0x02 DATA prefix.
// Uses an internal readBuf to prevent data loss when callers read in small chunks
// (e.g., crypto/tls reading a 5-byte TLS record header before the record body).
func (c *streamConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	select {
	case sf, ok := <-c.ch:
		if !ok {
			return 0, io.EOF
		}
		if sf.fh.Type == h2engine.FrameData && len(sf.payload) > 0 {
			switch sf.payload[0] {
			case 0x02: // DATA with chimney prefix
				data := sf.payload[1:]
				n := copy(p, data)
				if n < len(data) {
					c.readBuf = append(c.readBuf, data[n:]...)
				}
				return n, nil
			case 0x03: // CLOSE
				return 0, io.EOF
			default:
				// No chimney prefix — continuation of a fragmented write.
				// The entire payload is raw data.
				n := copy(p, sf.payload)
				if n < len(sf.payload) {
					c.readBuf = append(c.readBuf, sf.payload[n:]...)
				}
				return n, nil
			}
		}
		return 0, nil
	case <-c.t.quit:
		return 0, io.ErrClosedPipe
	}
}

// Write writes data to the stream, prefixing with 0x02 DATA command.
// If a traffic profile is configured, the record is padded to the target size.
func (c *streamConn) Write(p []byte) (int, error) {
	data := make([]byte, 1+len(p))
	data[0] = 0x02
	copy(data[1:], p)

	var targetSize uint16
	if c.t.prof != nil {
		if c.t.padTarget > 0 {
			targetSize = uint16(c.t.padTarget)
		} else {
			targetSize = c.t.prof.RecordSize()
		}
	}

	if targetSize > 0 {
		if err := c.t.h2Eng.WritePaddedRecord(c.streamID, data, targetSize, false); err != nil {
			return 0, err
		}
	} else {
		if err := c.t.h2Eng.WriteData(c.streamID, data, false); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// IsDead returns true when all tunnels' dispatch goroutines have exited,
// indicating the underlying connections are dead and a new dialer is needed.
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

// Close sends a CLOSE command and unregisters the stream.
func (c *streamConn) Close() error {
	c.t.h2Eng.WriteData(c.streamID, []byte{0x03}, false)
	c.t.mu.Lock()
	delete(c.t.streams, c.streamID)
	c.t.mu.Unlock()
	return nil
}

func (c *streamConn) LocalAddr() net.Addr  { return addr{"chimney", "client"} }
func (c *streamConn) RemoteAddr() net.Addr { return addr{"chimney", "relay"} }

func (c *streamConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

// newTunnel establishes a single H2-tunneled connection to the relay.
func newTunnel(config Config, prof *profile.Model, dil *dilution.Provider) (*tunnel, error) {
	// Step 1: TCP connect
	rawConn, err := net.DialTimeout("tcp", config.RelayAddr, config.ConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("chimney: connect to relay: %w", err)
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetReadBuffer(256 * 1024)
		tcpConn.SetWriteBuffer(256 * 1024)
		tcpConn.SetNoDelay(true)
	}

	// Step 2: uTLS handshake
	fpID, err := parseFingerprint(config.Fingerprint)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("chimney: %w", err)
	}

	tlsConfig := &utls.Config{
		ServerName:         config.SNI,
		InsecureSkipVerify: true,
	}

	uConn := utls.UClient(rawConn, tlsConfig, fpID)
	uConn.SetSNI(config.SNI)

	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("chimney: TLS handshake: %w", err)
	}

	serverRandom := uConn.HandshakeState.ServerHello.Random
	clientRandom := uConn.HandshakeState.Hello.Random

	if len(serverRandom) != 32 || len(clientRandom) != 32 {
		uConn.Close()
		return nil, fmt.Errorf("chimney: invalid random length")
	}

	// Step 3: Key derivation
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

	// Step 4: Drain stale TCP bytes.
	// Use a very short deadline — on clean connections (e.g. loopback)
	// this returns immediately; on real networks buffered data drains
	// within the first few reads without blocking tunnel setup.
	rawTCPConn := uConn.GetUnderlyingConn()
	rawTCPConn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	drainBuf := make([]byte, 8192)
	for {
		_, err := rawTCPConn.Read(drainBuf)
		if err != nil {
			break
		}
	}
	rawTCPConn.SetReadDeadline(time.Time{})

	// Step 5: Record layer
	recReader := record.NewRecordReader(rawTCPConn, codec)
	recWriter := record.NewRecordWriter(rawTCPConn, codec)

	// Step 6: Send H2 preface + SETTINGS
	settings := h2engine.DefaultSettings()
	h2Opening := h2engine.GenerateClientOpeningSequence(settings)
	if err := recWriter.WriteRecord(h2Opening); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: send H2 preface: %w", err)
	}

	// Step 7: Create H2 engine
	h2Eng := h2engine.NewEngine(settings, codec)
	h2Eng.SetRecordIO(recReader, recWriter)

	// Step 8: Complete H2 handshake
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

	// Step 9: Send auth tag
	authStreamID := h2Eng.OpenStream()
	authPayload := make([]byte, 4+len(tag))
	copy(authPayload, keyHint[:])
	copy(authPayload[4:], tag)
	tagFrame := h2engine.DataFrame(authStreamID, 0, authPayload)
	if err := recWriter.WriteRecord(tagFrame); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: send auth tag: %w", err)
	}

	t := &tunnel{
		rawConn:   rawTCPConn,
		h2Eng:     h2Eng,
		recReader: recReader,
		recWriter: recWriter,
		prof:      prof,
		padTarget: config.PaddingTarget,
		dilution:  dil,
		streams:   make(map[uint32]chan *streamFrame),
		quit:      make(chan struct{}),
		dead:      make(chan struct{}),
	}

	go t.dispatchFrames()
	if dil != nil && prof != nil {
		go t.dilutionLoop()
	}

	return t, nil
}

// NewDialer connects to a Chimney relay, establishes PoolSize TLS+H2 tunnels,
// and returns a Dialer ready to open streams via DialContext.
func NewDialer(config Config) (*Dialer, error) {
	if config.TagLen == 0 {
		config.TagLen = auth.DefaultTagLen
	}
	if config.Fingerprint == "" {
		config.Fingerprint = "chrome"
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = DefaultConnectTimeout
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if config.PoolSize <= 0 {
		config.PoolSize = DefaultPoolSize
	}

	if config.PSK == "" {
		if config.UserID == "" {
			config.UserID = "default"
		}
		config.PSK = hex.EncodeToString(auth.DerivePSKFromID(config.UserID))
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
			// Close already-created tunnels on partial failure.
			for j := 0; j < i; j++ {
				pool[j].closeTunnel()
			}
			return nil, err
		}
		pool[i] = t
	}

	return &Dialer{
		config:   config,
		pool:     pool,
		prof:     prof,
		dilution: dil,
	}, nil
}

// DialContext opens a new H2 stream through the Chimney tunnel to addr.
// The returned net.Conn is a virtual connection multiplexed over H2.
// Streams are distributed across the connection pool round-robin.
//
// network is ignored (always TCP). addr must be "host:port".
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	d.mu.Unlock()

	// Round-robin across the connection pool.
	idx := d.next.Add(1) % uint32(len(d.pool))
	t := d.pool[idx]

	return t.dialContext(ctx, addr)
}

// dialContext opens a stream on a single tunnel.
func (t *tunnel) dialContext(ctx context.Context, addr string) (net.Conn, error) {
	streamID := t.h2Eng.OpenStream()
	ch := make(chan *streamFrame, 256)

	t.mu.Lock()
	t.streams[streamID] = ch
	t.mu.Unlock()

	connectCmd := make([]byte, 1+len(addr))
	connectCmd[0] = 0x01
	copy(connectCmd[1:], addr)
	if err := t.h2Eng.WriteData(streamID, connectCmd, false); err != nil {
		t.mu.Lock()
		delete(t.streams, streamID)
		t.mu.Unlock()
		return nil, fmt.Errorf("chimney: CONNECT: %w", err)
	}

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
		case sf, ok := <-ch:
			if !ok {
				return nil, net.ErrClosed
			}
			if sf.fh.Type == h2engine.FrameData && len(sf.payload) > 0 {
				switch sf.payload[0] {
				case 0x01:
					return &streamConn{
						t:        t,
						streamID: streamID,
						ch:       ch,
					}, nil
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

// Close shuts down all tunnels in the pool.
func (d *Dialer) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.mu.Unlock()

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

	for _, ch := range t.streams {
		close(ch)
	}
	t.streams = nil
	t.mu.Unlock()

	t.recWriter.Close()
	return t.rawConn.Close()
}

// dispatchFrames reads frames from the H2 engine and routes them to per-stream channels.
func (t *tunnel) dispatchFrames() {
	defer close(t.dead)
	for {
		select {
		case <-t.quit:
			return
		default:
		}
		fh, payload, err := t.h2Eng.ReadFrame()
		if err != nil {
			t.mu.Lock()
			for _, ch := range t.streams {
				close(ch)
			}
			t.streams = make(map[uint32]chan *streamFrame)
			t.mu.Unlock()
			return
		}
		t.mu.Lock()
		ch, ok := t.streams[fh.StreamID]
		t.mu.Unlock()
		if ok {
			select {
			case ch <- &streamFrame{fh, payload}:
			default:
			}
		}
	}
}

// dilutionLoop periodically sends dilution records with real HTTP content.
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

// parseFingerprint maps a name string to a uTLS ClientHelloID.
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

	// Chinese browsers
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

// Ensure streamConn satisfies net.Conn at compile time.
var _ net.Conn = (*streamConn)(nil)

// Ensure crypto/tls is importable (utls.Config shadows it, but is never used directly).
var _ = tls.VersionTLS12

// RelayConfig holds the configuration for a Chimney relay server.
// This is the public API for creating a relay server from external packages.
type RelayConfig struct {
	// ListenAddr is the address to listen on (e.g. ":443").
	ListenAddr string

	// PSK is the pre-shared key (hex-encoded) for single-user mode.
	PSK string

	// Users maps user identifiers to their hex-encoded PSKs for multi-user mode.
	Users map[string]string

	// UserIDs is a list of user identifiers for multi-user mode.
	// Each user's PSK is derived as PSK = SHA256(userID).
	UserIDs []string

	// TagLen is the authentication tag length in bytes.
	TagLen int

	// IntentFile is the path to the intent whitelist file.
	// Ignored if IntentYAML is non-empty.
	IntentFile string

	// EnforceFile is the path to the enforce CIDR file.
	// Ignored if EnforceYAML is non-empty.
	EnforceFile string

	// IntentYAML is the inline intent whitelist YAML content.
	// When non-empty, takes precedence over IntentFile.
	IntentYAML string

	// EnforceYAML is the inline enforce CIDR YAML content.
	// When non-empty, takes precedence over EnforceFile.
	EnforceYAML string

	// CloudRegion is the cloud region for CIDR validation.
	CloudRegion string

	// DefaultBackend is the fallback backend for non-authenticated traffic.
	DefaultBackend string

	// HandshakeTimeout for TLS handshake relay.
	HandshakeTimeout time.Duration

	// AuthReadTimeout for reading the auth record.
	AuthReadTimeout time.Duration

	// EnableProfiling enables traffic profiling and pacing.
	EnableProfiling bool

	// ProfileDir is the directory containing site profile files.
	ProfileDir string

	// BackendDialer is an optional custom dialer for backend connections.
	BackendDialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

// RelayServer wraps the relay server for public consumption.
type RelayServer struct {
	srv *relay.Server
}

// NewRelayServer creates a new Chimney relay server.
// The server does NOT start listening until Start() is called.
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
	}
	srv, err := relay.NewServer(cfg, logger)
	if err != nil {
		return nil, err
	}
	return &RelayServer{srv: srv}, nil
}

// Start starts the relay server listener.
func (rs *RelayServer) Start() error {
	return rs.srv.Start()
}

// Stop stops the relay server and waits for active connections to drain.
func (rs *RelayServer) Stop() error {
	return rs.srv.Stop()
}

// Stats returns the relay server statistics.
func (rs *RelayServer) Stats() *relay.Stats {
	return rs.srv.Stats()
}
