// cmd/chimney-client is the Chimney client.
//
// The client connects to a Chimney relay, performs a real TLS handshake
// with a whitelisted site via the relay, embeds an auth tag in the first
// application_data record, and then establishes an H2 tunnel.
//
// Usage:
//
//	chimney-client -relay relay.example.com:443 -sni real-site.com -dest final-destination.com:443
//
// The client uses uTLS to mimic a real browser's TLS fingerprint.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/auth"
	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/keyderiv"
	"github.com/shuffleman/chimney-protocol/internal/record"
	utls "github.com/refraction-networking/utls"
)

const (
	// DefaultRelayTimeout is the timeout for relay connections.
	DefaultRelayTimeout = 10 * time.Second

	// DefaultHandshakeTimeout is the timeout for TLS handshake.
	DefaultHandshakeTimeout = 10 * time.Second
)

func main() {
	var (
		relayAddr  = flag.String("relay", "", "Relay address (host:port)")
		sni        = flag.String("sni", "", "SNI to use (whitelisted site)")
		destAddr   = flag.String("dest", "", "Final destination (host:port)")
		pskHex     = flag.String("psk", "", "Pre-shared key (hex-encoded)")
		tagLen     = flag.Int("tag-len", auth.DefaultTagLen, "Auth tag length")
		listenAddr = flag.String("listen", "127.0.0.1:1080", "Local SOCKS5 listen address")
	)
	flag.Parse()

	if *relayAddr == "" || *sni == "" || *destAddr == "" || *pskHex == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -relay <host:port> -sni <site> -dest <host:port> -psk <hex>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Create client
	client := &Client{
		RelayAddr:  *relayAddr,
		SNI:        *sni,
		DestAddr:   *destAddr,
		PSKHex:     *pskHex,
		TagLen:     *tagLen,
		ListenAddr: *listenAddr,
		Logger:     logger,
	}

	if err := client.Run(); err != nil {
		logger.Error("client failed", "error", err)
		os.Exit(1)
	}
}

// Client is the Chimney client.
type Client struct {
	RelayAddr  string
	SNI        string
	DestAddr   string
	PSKHex     string
	TagLen     int
	ListenAddr string
	Logger     *slog.Logger
}

// Run starts the client.
func (c *Client) Run() error {
	// Establish tunnel to relay
	tunnel, err := c.establishTunnel()
	if err != nil {
		return fmt.Errorf("establish tunnel: %w", err)
	}
	defer tunnel.Close()

	c.Logger.Info("tunnel established",
		"relay", c.RelayAddr,
		"sni", c.SNI,
		"dest", c.DestAddr,
	)

	// Start local SOCKS5 proxy that forwards through the tunnel
	return c.runSOCKS5(tunnel)
}

// establishTunnel establishes the Chimney tunnel to the relay.
//
// Protocol flow (revised for post-swap auth):
//  1. TCP connect to relay
//  2. TLS handshake with SNI=whitelisted site (uses uTLS Chrome fingerprint)
//  3. Extract ServerRandom & ClientRandom from handshake
//  4. Send a dummy first application_data record (TLS encrypted) as heuristic
//     trigger for the relay — contains minimal H2-like padding
//  5. Compute auth tag = HMAC(K_auth, ServerRandom || ClientRandom)
//  6. Derive K_sess from PSK + both randoms
//  7. Switch to ChimneyRecord layer (AEAD with K_sess)
//  8. Send H2 preface + SETTINGS as ChimneyRecords
//  9. Complete H2 handshake (SETTINGS + ACK exchange)
// 10. Send auth tag as first DATA frame on stream 1
// 11. Relay verifies post-swap; tunnel is ready
func (c *Client) establishTunnel() (net.Conn, error) {
	// Step 1: Connect to relay
	conn, err := net.DialTimeout("tcp", c.RelayAddr, DefaultRelayTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to relay: %w", err)
	}

	// Step 2: Perform TLS handshake with SNI=whitelisted site
	tlsConfig := &utls.Config{
		ServerName:         c.SNI,
		InsecureSkipVerify: true,
	}

	uConn := utls.UClient(conn, tlsConfig, utls.HelloChrome_Auto)
	uConn.SetSNI(c.SNI)

	if err := uConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	// Step 3: Extract handshake state
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

	// Step 4: Derive keys immediately after handshake.
	// The relay intercepts the first application_data record (0x17) at the
	// TLS record layer — no grace period or dummy record needed.
	deriver, err := keyderiv.NewDeriverFromHex(c.PSKHex)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("create deriver: %w", err)
	}

	// Compute auth tag = HMAC(K_auth, ServerRandom || ClientRandom)
	tag, err := deriver.AuthTag(serverRandom, clientRandom, c.TagLen)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("compute auth tag: %w", err)
	}

	// Derive directional keys for client side
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
		// Fallback to bidirectional
		kSess, _ := deriver.DeriveSessionKey(serverRandom, clientRandom)
		nonceBase, _ := deriver.DeriveNonceBase(serverRandom, clientRandom)
		codec, err = record.NewCodec(kSess, nonceBase)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("create record codec: %w", err)
		}
	}

	// Step 6: Drain stale bytes from TCP buffer before switching to ChimneyRecord.
	// The relay forwarded all server→client data during the handshake, including
	// any post-handshake records (e.g. NewSessionTicket). uTLS consumed what it
	// needed, but leftovers in the OS buffer would confuse the RecordReader.
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

	// Step 7: Wrap connection with ChimneyRecord layer (use raw TCP)
	recReader := record.NewRecordReader(rawConn, codec)
	recWriter := record.NewRecordWriter(rawConn, codec)

	c.Logger.Debug("codec created, sending H2 preface as ChimneyRecord")

	// Step 7: Send H2 preface + SETTINGS as ChimneyRecords
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

	// Create H2 engine
	h2Eng := h2engine.NewEngine(settings, codec)
	h2Eng.SetRecordIO(recReader, recWriter)

	// Step 8: Complete H2 handshake
	if err := c.completeH2Handshake(h2Eng, recWriter); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("H2 handshake: %w", err)
	}

	// Step 9: Send auth tag as first DATA frame on stream 1
	authStreamID := h2Eng.OpenStream()
	tagFrame := h2engine.DataFrame(authStreamID, 0, tag)
	if err := recWriter.WriteRecord(tagFrame); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("send auth tag frame: %w", err)
	}

	c.Logger.Debug("sent post-swap auth tag", "tag", hex.EncodeToString(tag), "stream", authStreamID)

	// Step 10: Wait for relay's auth confirmation (empty DATA frame or SETTINGS ACK)
	// The relay sends a new SETTINGS frame or just proceeds — if we get here
	// without error, the tunnel is established

	c.Logger.Info("Chimney tunnel established")

	return newTunnelConn(rawConn, h2Eng, recReader, recWriter), nil
}

// completeH2Handshake completes the H2 handshake after the swap.
func (c *Client) completeH2Handshake(h2Eng *h2engine.Engine, recWriter *record.RecordWriter) error {
	// As client, we've already sent preface + SETTINGS
	// Now we need to:
	// 1. Receive server SETTINGS
	// 2. Send SETTINGS ACK
	// 3. Receive server SETTINGS ACK

	// Read server SETTINGS
	fh, _, err := h2Eng.ReadFrame()
	if err != nil {
		return fmt.Errorf("read server SETTINGS: %w", err)
	}
	if fh.Type != h2engine.FrameSettings {
		return fmt.Errorf("expected SETTINGS, got frame type 0x%x", fh.Type)
	}

	// Send SETTINGS ACK
	ackFrame := h2engine.DefaultSettings().EncodeSettings(true)
	if err := recWriter.WriteRecord(ackFrame); err != nil {
		return fmt.Errorf("send SETTINGS ACK: %w", err)
	}

	// Read server SETTINGS ACK
	fh, _, err = h2Eng.ReadFrame()
	if err != nil {
		return fmt.Errorf("read SETTINGS ACK: %w", err)
	}
	if fh.Type != h2engine.FrameSettings || fh.Flags&h2engine.FlagAck == 0 {
		return fmt.Errorf("expected SETTINGS ACK, got frame type 0x%x flags 0x%x", fh.Type, fh.Flags)
	}

	return nil
}

// runSOCKS5 runs a local SOCKS5 proxy that forwards through the tunnel.
func (c *Client) runSOCKS5(tunnel net.Conn) error {
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

		go c.handleSOCKS5Conn(conn, tunnel)
	}
}

// handleSOCKS5Conn handles a single SOCKS5 connection.
func (c *Client) handleSOCKS5Conn(clientConn net.Conn, tunnel net.Conn) {
	defer clientConn.Close()

	tc := tunnel.(*tunnelConn)

	// SOCKS5 handshake
	if err := c.socks5Handshake(clientConn); err != nil {
		c.Logger.Debug("SOCKS5 handshake failed", "error", err)
		return
	}

	// Read connect request
	targetAddr, err := c.socks5ReadRequest(clientConn)
	if err != nil {
		c.Logger.Debug("SOCKS5 request failed", "error", err)
		return
	}

	c.Logger.Debug("SOCKS5 connect", "target", targetAddr)

	// Open a tunnel stream to the target via the relay
	stream, err := tc.openStream(targetAddr)
	if err != nil {
		c.Logger.Debug("tunnel stream open failed", "error", err)
		c.socks5SendReply(clientConn, 0x01) // General SOCKS server failure
		return
	}
	defer stream.Close()

	// Send SOCKS5 success reply
	if err := c.socks5SendReply(clientConn, 0x00); err != nil {
		return
	}

	// Bidirectional relay between SOCKS5 client and tunnel stream
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer clientConn.Close() // Unblock the other goroutine's Read
		io.Copy(stream, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, stream)
	}()

	wg.Wait()
}

// socks5Handshake performs the SOCKS5 authentication handshake.
func (c *Client) socks5Handshake(conn net.Conn) error {
	// Read auth methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Reply with no auth (0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}

	return nil
}

// socks5ReadRequest reads the SOCKS5 connect request.
func (c *Client) socks5ReadRequest(conn net.Conn) (string, error) {
	// Read fixed header
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != 0x05 || header[1] != 0x01 { // Must be CONNECT
		return "", fmt.Errorf("unsupported SOCKS5 command: %d", header[1])
	}

	// Read address
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

	case 0x03: // Domain name
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

// socks5SendReply sends a SOCKS5 reply.
func (c *Client) socks5SendReply(conn net.Conn, code byte) error {
	reply := []byte{0x05, code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(reply)
	return err
}

// streamFrame is a frame received for a specific H2 stream.
type streamFrame struct {
	fh      *h2engine.FrameHeader
	payload []byte
}

// tunnelConn wraps the raw TCP connection with H2 stream multiplexing.
type tunnelConn struct {
	net.Conn
	h2Engine  *h2engine.Engine
	recReader *record.RecordReader
	recWriter *record.RecordWriter

	mu      sync.Mutex
	streams map[uint32]chan *streamFrame
	quit    chan struct{}
}

// newTunnelConn creates a tunnelConn and starts its frame dispatcher.
func newTunnelConn(rawConn net.Conn, h2Eng *h2engine.Engine, recReader *record.RecordReader, recWriter *record.RecordWriter) *tunnelConn {
	tc := &tunnelConn{
		Conn:      rawConn,
		h2Engine:  h2Eng,
		recReader: recReader,
		recWriter: recWriter,
		streams:   make(map[uint32]chan *streamFrame),
		quit:      make(chan struct{}),
	}
	go tc.dispatchFrames()
	return tc
}

// dispatchFrames reads frames from the H2 engine and routes them to per-stream channels.
func (tc *tunnelConn) dispatchFrames() {
	for {
		select {
		case <-tc.quit:
			return
		default:
		}
		fh, payload, err := tc.h2Engine.ReadFrame()
		if err != nil {
			tc.mu.Lock()
			for _, ch := range tc.streams {
				close(ch)
			}
			tc.streams = make(map[uint32]chan *streamFrame)
			tc.mu.Unlock()
			return
		}
		tc.mu.Lock()
		ch, ok := tc.streams[fh.StreamID]
		tc.mu.Unlock()
		if ok {
			select {
			case ch <- &streamFrame{fh, payload}:
			default:
			}
		}
	}
}

// openStream opens a new H2 stream and sends a CONNECT command to the relay.
func (tc *tunnelConn) openStream(dest string) (*tunnelStream, error) {
	streamID := tc.h2Engine.OpenStream()
	ch := make(chan *streamFrame, 16)

	tc.mu.Lock()
	tc.streams[streamID] = ch
	tc.mu.Unlock()

	// Send CONNECT command
	connectCmd := make([]byte, 1+len(dest))
	connectCmd[0] = 0x01
	copy(connectCmd[1:], dest)
	if err := tc.h2Engine.WriteData(streamID, connectCmd, false); err != nil {
		tc.mu.Lock()
		delete(tc.streams, streamID)
		tc.mu.Unlock()
		return nil, err
	}

	// Wait for CONNECT_OK
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
		case <-timeout.C:
			tc.mu.Lock()
			delete(tc.streams, streamID)
			tc.mu.Unlock()
			return nil, fmt.Errorf("CONNECT timeout")
		}
	}
}

// tunnelStream is a single H2 stream within the tunnel.
type tunnelStream struct {
	tc       *tunnelConn
	streamID uint32
	ch       chan *streamFrame
}

// Read reads data from the stream, stripping the 0x02 DATA prefix.
func (ts *tunnelStream) Read(p []byte) (int, error) {
	sf, ok := <-ts.ch
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
}

// Write writes data to the stream, prefixing with 0x02 DATA command.
func (ts *tunnelStream) Write(p []byte) (int, error) {
	data := make([]byte, 1+len(p))
	data[0] = 0x02
	copy(data[1:], p)
	if err := ts.tc.h2Engine.WriteData(ts.streamID, data, false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close sends a CLOSE command and unregisters the stream.
func (ts *tunnelStream) Close() error {
	ts.tc.h2Engine.WriteData(ts.streamID, []byte{0x03}, false)
	ts.tc.mu.Lock()
	delete(ts.tc.streams, ts.streamID)
	ts.tc.mu.Unlock()
	return nil
}
