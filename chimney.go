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
package chimney

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/auth"
	"github.com/shuffleman/chimney-protocol/internal/dilution"
	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/keyderiv"
	"github.com/shuffleman/chimney-protocol/internal/profile"
	"github.com/shuffleman/chimney-protocol/internal/record"

	utls "github.com/refraction-networking/utls"
)

const (
	// DefaultConnectTimeout is the default timeout for establishing the tunnel.
	DefaultConnectTimeout = 10 * time.Second

	// DefaultHandshakeTimeout is the default timeout for TLS + H2 handshake.
	DefaultHandshakeTimeout = 10 * time.Second
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
}

// A Dialer represents an established Chimney tunnel to a relay.
// Multiple goroutines may invoke DialContext concurrently; each call opens
// an independent H2 stream multiplexed over the same TLS connection.
type Dialer struct {
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
	closed  bool
}

// streamFrame is a frame received for a specific H2 stream.
type streamFrame struct {
	fh      *h2engine.FrameHeader
	payload []byte
}

// streamConn wraps a single H2 stream as a net.Conn.
type streamConn struct {
	d        *Dialer
	streamID uint32
	ch       chan *streamFrame

	readDeadline  time.Time
	writeDeadline time.Time
}

// addr is a trivial net.Addr implementation.
type addr struct{ network, str string }

func (a addr) Network() string { return a.network }
func (a addr) String() string  { return a.str }

// Read reads data from the stream, stripping the 0x02 DATA prefix.
func (c *streamConn) Read(p []byte) (int, error) {
	select {
	case sf, ok := <-c.ch:
		if !ok {
			return 0, io.EOF
		}
		if sf.fh.Type == h2engine.FrameData && len(sf.payload) > 0 {
			switch sf.payload[0] {
			case 0x02: // DATA
				return copy(p, sf.payload[1:]), nil
			case 0x03: // CLOSE
				return 0, io.EOF
			}
		}
		return 0, nil
	case <-c.d.quit:
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
	if c.d.prof != nil {
		if c.d.padTarget > 0 {
			targetSize = uint16(c.d.padTarget)
		} else {
			targetSize = c.d.prof.RecordSize()
		}
	}

	if targetSize > 0 {
		if err := c.d.h2Eng.WritePaddedRecord(c.streamID, data, targetSize, false); err != nil {
			return 0, err
		}
	} else {
		if err := c.d.h2Eng.WriteData(c.streamID, data, false); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Close sends a CLOSE command and unregisters the stream.
func (c *streamConn) Close() error {
	c.d.h2Eng.WriteData(c.streamID, []byte{0x03}, false)
	c.d.mu.Lock()
	delete(c.d.streams, c.streamID)
	c.d.mu.Unlock()
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

// NewDialer connects to a Chimney relay, establishes a TLS + H2 tunnel,
// and returns a Dialer ready to open streams via DialContext.
func NewDialer(config Config) (*Dialer, error) {
	// Apply defaults
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

	// Derive PSK from UserID if no explicit PSK is given.
	if config.PSK == "" {
		if config.UserID == "" {
			config.UserID = "default"
		}
		config.PSK = hex.EncodeToString(auth.DerivePSKFromID(config.UserID))
	}

	// Step 1: TCP connect
	rawConn, err := net.DialTimeout("tcp", config.RelayAddr, config.ConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("chimney: connect to relay: %w", err)
	}

	// Step 2: uTLS handshake
	fpID, err := parseFingerprint(config.Fingerprint)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("chimney: %w", err)
	}

	tlsConfig := &utls.Config{
		ServerName:         config.SNI,
		InsecureSkipVerify: true, // relay forwards to real site
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

	// Compute key hint for multi-user auth.
	// If no UserID is set, default to "default" for single-user compatibility.
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
		// Fallback to bidirectional
		kSess, _ := deriver.DeriveSessionKey(serverRandom, clientRandom)
		nonceBase, _ := deriver.DeriveNonceBase(serverRandom, clientRandom)
		codec, err = record.NewCodec(kSess, nonceBase)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("chimney: create codec: %w", err)
		}
	}

	// Step 4: Drain stale TCP bytes
	rawTCPConn := uConn.GetUnderlyingConn()
	rawTCPConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
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

	// Step 8: Complete H2 handshake (read server SETTINGS → send ACK → read ACK)
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

	// Step 9: Send auth tag with key hint prefix.
	// Extended auth frame format: [key_hint (4 bytes)] [tag (tagLen bytes)]
	authStreamID := h2Eng.OpenStream()
	authPayload := make([]byte, 4+len(tag))
	copy(authPayload, keyHint[:])
	copy(authPayload[4:], tag)
	tagFrame := h2engine.DataFrame(authStreamID, 0, authPayload)
	if err := recWriter.WriteRecord(tagFrame); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: send auth tag: %w", err)
	}

	// Step 10: Load optional profile and dilution
	var prof *profile.Model
	if config.ProfilePath != "" {
		prof, err = profile.LoadModelFromFile(config.ProfilePath)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("chimney: load profile: %w", err)
		}
	}

	var dil *dilution.Provider
	if config.DilutionPath != "" {
		dil, err = dilution.LoadProviderFromFile(config.DilutionPath)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("chimney: load dilution: %w", err)
		}
	}

	d := &Dialer{
		rawConn:   rawTCPConn,
		h2Eng:     h2Eng,
		recReader: recReader,
		recWriter: recWriter,
		prof:      prof,
		padTarget: config.PaddingTarget,
		dilution:  dil,
		streams:   make(map[uint32]chan *streamFrame),
		quit:      make(chan struct{}),
	}

	go d.dispatchFrames()
	if dil != nil && prof != nil {
		go d.dilutionLoop()
	}

	return d, nil
}

// DialContext opens a new H2 stream through the Chimney tunnel to addr.
// The returned net.Conn is a virtual connection multiplexed over H2.
//
// network is ignored (always TCP). addr must be "host:port".
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, net.ErrClosed
	}
	d.mu.Unlock()

	streamID := d.h2Eng.OpenStream()
	ch := make(chan *streamFrame, 16)

	d.mu.Lock()
	d.streams[streamID] = ch
	d.mu.Unlock()

	// Send CONNECT command
	connectCmd := make([]byte, 1+len(addr))
	connectCmd[0] = 0x01
	copy(connectCmd[1:], addr)
	if err := d.h2Eng.WriteData(streamID, connectCmd, false); err != nil {
		d.mu.Lock()
		delete(d.streams, streamID)
		d.mu.Unlock()
		return nil, fmt.Errorf("chimney: CONNECT: %w", err)
	}

	// Wait for CONNECT_OK or context cancellation
	for {
		select {
		case <-ctx.Done():
			d.mu.Lock()
			delete(d.streams, streamID)
			d.mu.Unlock()
			return nil, ctx.Err()
		case <-d.quit:
			d.mu.Lock()
			delete(d.streams, streamID)
			d.mu.Unlock()
			return nil, net.ErrClosed
		case sf, ok := <-ch:
			if !ok {
				return nil, net.ErrClosed
			}
			if sf.fh.Type == h2engine.FrameData && len(sf.payload) > 0 {
				switch sf.payload[0] {
				case 0x01: // CONNECT_OK
					return &streamConn{
						d:        d,
						streamID: streamID,
						ch:       ch,
					}, nil
				default:
					d.mu.Lock()
					delete(d.streams, streamID)
					d.mu.Unlock()
					return nil, fmt.Errorf("chimney: backend connect failed: code 0x%02x", sf.payload[0])
				}
			}
		}
	}
}

// Close shuts down the Chimney tunnel and all active streams.
func (d *Dialer) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	close(d.quit)

	// Close all stream channels
	for _, ch := range d.streams {
		close(ch)
	}
	d.streams = nil
	d.mu.Unlock()

	return d.rawConn.Close()
}

// dispatchFrames reads frames from the H2 engine and routes them to per-stream channels.
func (d *Dialer) dispatchFrames() {
	for {
		select {
		case <-d.quit:
			return
		default:
		}
		fh, payload, err := d.h2Eng.ReadFrame()
		if err != nil {
			d.mu.Lock()
			for _, ch := range d.streams {
				close(ch)
			}
			d.streams = make(map[uint32]chan *streamFrame)
			d.mu.Unlock()
			return
		}
		d.mu.Lock()
		ch, ok := d.streams[fh.StreamID]
		d.mu.Unlock()
		if ok {
			select {
			case ch <- &streamFrame{fh, payload}:
			default:
			}
		}
	}
}

// dilutionLoop periodically sends dilution records with real HTTP content.
func (d *Dialer) dilutionLoop() {
	interval := d.prof.RecordDelay()
	if interval <= 0 {
		interval = 2 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.quit:
			return
		case <-ticker.C:
			targetSize := d.prof.RecordSize()
			content := d.dilution.GetBlock(targetSize)
			if content == nil {
				continue
			}
			if err := d.h2Eng.WriteDilutionRecord(content, targetSize); err != nil {
				return
			}
			nextInterval := d.prof.RecordDelay()
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
