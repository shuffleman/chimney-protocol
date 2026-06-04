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
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	// DefaultConnectTimeout is the default timeout for establishing the tunnel.
	DefaultConnectTimeout = 10 * time.Second

	// DefaultHandshakeTimeout is the default timeout for TLS + H2 handshake.
	DefaultHandshakeTimeout = 10 * time.Second

	// DefaultPoolSize is the default number of parallel H2 connections.
	DefaultPoolSize = 4

	// DefaultTCPBufferSize is the default TCP read/write buffer size per tunnel.
	DefaultTCPBufferSize = 256 * 1024
)

// Config holds all parameters for establishing a Chimney tunnel.
// RelayAddr, SNI, and either PSK or UserID are required; all other fields have
// defaults. Config is safe to embed in downstream project configuration structs.
type Config struct {
	// RelayAddr is the relay server address (host:port). Required.
	RelayAddr string `yaml:"relay_addr" json:"relay_addr"`

	// SNI is the TLS Server Name Indication — must be a whitelisted site. Required.
	SNI string `yaml:"sni" json:"sni"`

	// PSK is the pre-shared key (64 hex chars = 256 bits). Optional when UserID
	// is set; in that mode PSK is derived as SHA256(UserID).
	PSK string `yaml:"psk,omitempty" json:"psk,omitempty"`

	// UserID is the user identifier (e.g. UUID) for multi-user relay deployments.
	// It is hashed to a 4-byte key hint sent alongside the auth tag.
	// If empty, defaults to "default" (single-user mode).
	UserID string `yaml:"user_id,omitempty" json:"user_id,omitempty"`

	// TagLen is the auth tag length in bytes (default: 16).
	TagLen int `yaml:"tag_len,omitempty" json:"tag_len,omitempty"`

	// Fingerprint is the uTLS ClientHello fingerprint name (default: "chrome").
	// Available: chrome, firefox, safari, ios, edge, android, 360, qq,
	// randomized, golang — with optional -version (e.g. "chrome-120").
	Fingerprint string `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`

	// ProfilePath is an optional traffic profile JSON for padding.
	// Empty string disables padding.
	ProfilePath string `yaml:"profile_path,omitempty" json:"profile_path,omitempty"`

	// PaddingTarget overrides the padding record size. 0 = use profile distribution.
	PaddingTarget int `yaml:"padding_target,omitempty" json:"padding_target,omitempty"`

	// DilutionPath is an optional content blocks JSON for the dilution stream.
	// Empty string disables dilution.
	DilutionPath string `yaml:"dilution_path,omitempty" json:"dilution_path,omitempty"`

	// ConnectTimeout is the TCP connect timeout (default: 10s).
	ConnectTimeout time.Duration `yaml:"connect_timeout,omitempty" json:"connect_timeout,omitempty"`

	// HandshakeTimeout is the TLS + H2 handshake timeout (default: 10s).
	HandshakeTimeout time.Duration `yaml:"handshake_timeout,omitempty" json:"handshake_timeout,omitempty"`

	// PoolSize is the number of parallel H2 connections to the relay (default: 4).
	// Higher values increase throughput under high concurrency by parallelising
	// frame dispatch across multiple TCP sockets. Set to 1 for single-connection
	// mode (lowest resource usage, sufficient for low concurrency).
	PoolSize int `yaml:"pool_size,omitempty" json:"pool_size,omitempty"`

	// TCPBufferSize sets the TCP read/write buffer size in bytes for each tunnel
	// connection (default: 262144 = 256 KiB). On memory-constrained platforms
	// like iOS, reduce to 65536 to save ~384 KiB per tunnel.
	TCPBufferSize int `yaml:"tcp_buffer_size,omitempty" json:"tcp_buffer_size,omitempty"`
}

// DefaultConfig returns a Config populated with library defaults.
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

// ConfigFromYAML parses a Chimney client-library config from YAML, applies
// defaults, and validates it. It is intended for downstream projects that want
// to embed Chimney as a transport without importing internal packages.
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

// LoadConfigFile loads a Chimney client-library config from a YAML file.
func LoadConfigFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("chimney: read config: %w", err)
	}
	return ConfigFromYAML(data)
}

// Normalize applies defaults, derives PSK from UserID when needed, and validates
// the config. It is useful when downstream projects construct Config manually.
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
	if _, err := parseFingerprint(c.Fingerprint); err != nil {
		return fmt.Errorf("chimney: %w", err)
	}
	return nil
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

	mu        sync.Mutex
	streams   map[uint32]chan *streamFrame
	quit      chan struct{}
	dead      chan struct{}
	closed    bool
	lastError error // set when dispatchFrames exits on read error
}

// LastError returns the error that caused dispatchFrames to exit, if any.
func (t *tunnel) LastError() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastError
}

// CodecTrails returns the sealer and opener trails from the H2 engine's record codec.
func (t *tunnel) CodecTrails() (sealerTrail, openerTrail string) {
	return t.h2Eng.CodecTrails()
}

// CodecSeqs returns the current sealer and opener sequence numbers.
func (t *tunnel) CodecSeqs() (sealerSeq, openerSeq uint64) {
	return t.h2Eng.CodecSeqs()
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
	dialNew  func(Config, *profile.Model, *dilution.Provider) (*tunnel, error)
}

// Diagnostics returns diagnostic information from all tunnels in the pool.
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

// streamFrame is a frame received for a specific H2 stream.
type streamFrame struct {
	fh      *h2engine.FrameHeader
	payload []byte
}

// writeBufPool reuses Write buffers up to DefaultMaxFrameSize+1 bytes.
// Larger buffers fall through to heap allocation.
var writeBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 65536+1)
		return &buf
	},
}

// streamConn wraps a single H2 stream as a net.Conn.
type streamConn struct {
	t        *tunnel
	streamID uint32
	ch       chan *streamFrame
	cmd      byte // cmdTCP for TCP streams, cmdUDP for UDP streams

	readMu  sync.Mutex
	readBuf []byte // leftover data from partial read of an H2 frame payload

	closeOnce sync.Once
	closed    chan struct{}

	deadlineMu          sync.Mutex
	readDeadline        time.Time
	writeDeadline       time.Time
	readDeadlineChanged chan struct{}
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

// addr is a trivial net.Addr implementation.
type addr struct{ network, str string }

func (a addr) Network() string { return a.network }
func (a addr) String() string  { return a.str }

// Read reads data from the stream, stripping the 0x02 DATA prefix.
// Uses an internal readBuf to prevent data loss when callers read in small chunks
// (e.g., crypto/tls reading a 5-byte TLS record header before the record body).
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
				case 0x02: // DATA with chimney prefix
					data := sf.payload[1:]
					n := copy(p, data)
					if n < len(data) {
						c.readMu.Lock()
						c.readBuf = append(c.readBuf, data[n:]...)
						c.readMu.Unlock()
					}
					return n, nil
				case 0x03: // CLOSE
					return 0, io.EOF
				default:
					// No chimney prefix — continuation of a fragmented write.
					// The entire payload is raw data.
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

// Write writes data to the stream, prefixing with 0x02 DATA command.
// If a traffic profile is configured, the record is padded to the target size.
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

	var targetSize uint16
	if c.t.prof != nil {
		if c.t.padTarget > 0 {
			targetSize = uint16(c.t.padTarget)
		} else {
			targetSize = c.t.prof.RecordSize()
		}
	}

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

	// Use pool for typical frame sizes; allocate directly for oversized writes.
	var data []byte
	var poolPtr *[]byte
	if needed <= 65537 {
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

	if targetSize > 0 {
		return c.t.h2Eng.WritePaddedRecord(c.streamID, data, targetSize, false)
	}
	return c.t.h2Eng.WriteData(c.streamID, data, false)
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

// LastError returns the last dispatch error from any tunnel, or nil.
// Useful for diagnosing why the dialer died.
func (d *Dialer) LastError() error {
	for _, t := range d.pool {
		if err := t.LastError(); err != nil {
			return err
		}
	}
	return nil
}

// Close sends a CLOSE command and unregisters the stream.
func (c *streamConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.t != nil && c.t.h2Eng != nil {
			err = c.t.h2Eng.WriteData(c.streamID, []byte{cmdClose}, false)
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

	// Drain buffered frames so payloads can be GC'd immediately.
	// The channel is not closed here — closing would race with
	// dispatchFrames, which may have already fetched the channel
	// reference. The channel is GC'd when this streamConn goes out
	// of scope, and any remaining buffered frames at tunnel shutdown
	// are cleaned up by closeTunnel.
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
// UDP support — net.PacketConn over Chimney H2 streams.
//
// Like other stream-tunnel protocols (VLESS, Trojan, Shadowsocks), all UDP
// datagrams for one PacketConn are multiplexed over one H2 stream. H2 DATA
// frames provide natural message boundaries so no length-prefix is needed.
// ---------------------------------------------------------------------------

// Command byte prepended to H2 DATA frame payloads so the relay can
// distinguish TCP streams from UDP streams.
const (
	cmdTCP   = 0x02 // TCP data
	cmdClose = 0x03 // Stream close
	cmdUDP   = 0x04 // UDP datagram

	// maxTunnelDataChunk leaves one byte for the Chimney tunnel command prefix
	// so every TCP H2 DATA frame carries its own cmdTCP byte.
	maxTunnelDataChunk = 16*1024 - 1
)

// UDP datagram wire format within a DATA frame payload:
//
//	[1B cmd=0x04][1B addrType][addr][2B port][payload]
//
// addrType: 0x01 = IPv4 (4B), 0x03 = Domain (1B len + N bytes), 0x04 = IPv6 (16B)

// udpConn implements net.PacketConn over a single Chimney H2 stream.
// All datagrams share one stream; H2 DATA frame boundaries delimit messages.
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

// Ensure udpConn satisfies net.PacketConn.
var _ net.PacketConn = (*udpConn)(nil)

// ReadFrom reads a UDP datagram, returning the payload and source address.
func (u *udpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		u.mu.Lock()
		if u.closed {
			u.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		deadline := u.readDeadline
		u.mu.Unlock()

		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timeout = time.After(time.Until(deadline))
		}

		select {
		case sf, ok := <-u.stream.ch:
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
		case <-timeout:
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: &timeoutError{}}
		case <-u.stream.closed:
			return 0, nil, net.ErrClosed
		case <-u.t.quit:
			return 0, nil, io.ErrClosedPipe
		case <-u.readDeadlineChangedChan():
			continue
		}
	}
}

// parseDatagram extracts a UDP datagram from a DATA frame payload.
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
	case 0x03: // Domain
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

// encodeDatagram builds the wire format for a UDP datagram (without command byte;
// streamConn.Write prepends the correct cmd based on the stream type).
func encodeDatagram(addr net.Addr, b []byte) []byte {
	host, port, ok := udpAddrParts(addr)
	if !ok {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if len(host) == 0 || len(host) > 255 {
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

// WriteTo sends a UDP datagram to the given address.
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

// Close closes the UDP stream.
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

// ListenPacket opens a UDP packet connection over the Chimney tunnel.
// A single H2 stream carries all UDP datagrams; H2 DATA frame boundaries
// provide natural message delimiting.
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

	ch := make(chan *streamFrame, 256)
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

// newTunnel establishes a single H2-tunneled connection to the relay.
func newTunnel(config Config, prof *profile.Model, dil *dilution.Provider) (*tunnel, error) {
	// Step 1: TCP connect
	rawConn, err := net.DialTimeout("tcp", config.RelayAddr, config.ConnectTimeout)
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

	// Step 4: Extract raw TCP connection for the record layer.
	// After the swap the Chimney record codec operates directly on the
	// TCP stream — TLS is no longer in the picture.
	rawTCPConn := uConn.GetUnderlyingConn()

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
	if err := rawTCPConn.SetDeadline(time.Time{}); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("chimney: clear handshake deadline: %w", err)
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
		dialNew:  newTunnel,
	}, nil
}

// ensureTunnel returns the tunnel at pool[idx], replacing it with a fresh one
// if the existing tunnel's dispatch goroutine has already exited. Only one
// goroutine replaces a given slot at a time; concurrent callers block on d.mu
// and then reuse the tunnel that was just created.
func (d *Dialer) ensureTunnel(idx uint32) (*tunnel, error) {
	t := d.pool[idx]
	select {
	case <-t.dead:
		// Tunnel is dead — attempt to replace it.
	default:
		return t, nil // still alive
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil, net.ErrClosed
	}

	// Re-check under lock: another goroutine may have already replaced it.
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
	poolLen := len(d.pool)
	d.mu.Unlock()

	if poolLen == 0 {
		return nil, fmt.Errorf("chimney: no tunnels available")
	}

	// Round-robin across the connection pool, auto-reconnecting dead tunnels.
	// If one slot cannot reconnect, try the remaining slots before surfacing
	// the error to callers such as sing-box.
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

// dialContext opens a stream on a single tunnel.
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
	t.mu.Unlock()

	t.recWriter.Close()
	err := t.rawConn.Close()
	<-t.dead
	return err
}

// dispatchFrames reads frames from the H2 engine and routes them to per-stream channels.
// tunnelIdleTimeout is the maximum duration with no frames received before
// the tunnel is considered dead and torn down. This prevents dispatchFrames
// from blocking forever on a stuck Windows TCP loopback connection.
const tunnelIdleTimeout = 30 * time.Second

func (t *tunnel) dispatchFrames() {
	defer close(t.dead)

	// Rolling read deadline: extended after every successful ReadFrame so
	// active tunnels never time out; stuck connections are detected within
	// tunnelIdleTimeout seconds.
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
		// Extend deadline on every successful frame receipt.
		t.rawConn.SetReadDeadline(time.Now().Add(tunnelIdleTimeout))

		t.mu.Lock()
		ch, ok := t.streams[fh.StreamID]
		t.mu.Unlock()
		if ok {
			// Fast path: channel has space — no timer allocation.
			select {
			case ch <- &streamFrame{fh, payload}:
			default:
				// Slow path: channel is full. Wait with a timeout — a consumer
				// stuck for tunnelIdleTimeout starves the TCP receive buffer and
				// deadlocks the tunnel, so tear it down if necessary.
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
