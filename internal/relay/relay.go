// Package relay implements the core relay logic: TCP forwarding, handshake relay,
// auth verification, swap (调包), and tunnel establishment (Part II §6-§12).
//
// The relay is the central component of Chimney. For each client connection:
//
//  1. Read ClientHello, extract SNI
//  2. Check whitelist (关卡A: SNI intent, 关卡B: destination IP)
//  3. If either check fails → passive fallback (forward to default backend
//     or close naturally, indistinguishable from real site)
//  4. Forward TLS handshake to real site (pure TCP relay, no decryption)
//  5. Observe ServerHello, extract ServerRandom
//  6. After handshake, read first application_data record from client
//  7. Compute expected auth tag, compare with embedded tag
//  8. If tag matches → swap: cut real site, take over with K_sess
//  9. If tag doesn't match → continue forwarding to real site (zero distinction)
// 10. In Chimney mode: H2 framing, tunneling, profile pacing
package relay

import (
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
	// DefaultListenAddr is the default relay listen address.
	DefaultListenAddr = ":443"

	// HandshakeTimeout is the maximum time allowed for TLS handshake relay.
	HandshakeTimeout = 10 * time.Second

	// AuthReadTimeout is the timeout for reading the first application_data
	// record containing the auth tag.
	AuthReadTimeout = 5 * time.Second

	// TCPBufferSize is the buffer size for TCP relay.
	TCPBufferSize = 32 * 1024

)

var (
	// ErrHandshakeTimeout is returned when the TLS handshake takes too long.
	ErrHandshakeTimeout = errors.New("relay: TLS handshake timeout")

	// ErrAuthFailed is returned when the auth tag verification fails.
	// This is NOT a distinguishable error — the caller should continue
	// forwarding to the real site.
	ErrAuthFailed = errors.New("relay: authentication failed")

	// ErrSwapFailed is returned when the swap operation fails.
	ErrSwapFailed = errors.New("relay: swap failed")

	// ErrWhitelistFailed is returned when whitelist checks fail.
	// This triggers passive fallback.
	ErrWhitelistFailed = errors.New("relay: whitelist check failed")
)

// Server is the Chimney relay server.
type Server struct {
	// Configuration
	config *Config

	// Components
	whitelistMgr *whitelist.Manager
	userStore    *auth.UserStore

	// Statistics
	stats *Stats

	// Logger
	logger *slog.Logger

	// Listener
	listener net.Listener

	// Active connections
	wg     sync.WaitGroup
	mu     sync.RWMutex
	closed atomic.Bool
}

// Config holds the relay server configuration.
type Config struct {
	// ListenAddr is the address to listen on.
	ListenAddr string

	// PSK is the pre-shared key (hex-encoded). For single-user mode only.
	// If Users is non-empty, PSK is ignored.
	PSK string

	// Users maps user identifiers (e.g. UUIDs) to their hex-encoded PSKs.
	// When set, multi-user authentication with key-hint lookup is enabled.
	Users map[string]string

	// UserIDs is a list of user identifiers (e.g. UUIDs) for multi-user mode.
	// Each user's PSK is derived as PSK = SHA256(userID).
	// This is the recommended field — no need to specify separate PSK values.
	// If both Users and UserIDs are set, Users takes precedence.
	UserIDs []string

	// TagLen is the authentication tag length.
	TagLen int

	// IntentFile is the path to the intent whitelist file.
	IntentFile string

	// EnforceFile is the path to the enforce CIDR file.
	EnforceFile string

	// CloudRegion is the cloud region for CIDR validation (e.g., "us-east-1").
	CloudRegion string

	// DefaultBackend is the fallback backend for non-authenticated traffic.
	// If empty, connections are closed naturally on whitelist/auth failure.
	DefaultBackend string

	// HandshakeTimeout for TLS handshake relay.
	HandshakeTimeout time.Duration

	// AuthReadTimeout for reading the auth record.
	AuthReadTimeout time.Duration

	// EnableProfiling enables traffic profiling and pacing.
	EnableProfiling bool

	// ProfileDir is the directory containing site profile files.
	ProfileDir string
}

// DefaultConfig returns a default configuration.
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

// Stats holds relay statistics.
type Stats struct {
	TotalConnections    atomic.Uint64
	ActiveConnections   atomic.Int64
	AuthenticatedSwaps  atomic.Uint64
	AuthFailures        atomic.Uint64
	WhitelistRejections atomic.Uint64
	RelayBytesUp        atomic.Uint64
	RelayBytesDown      atomic.Uint64
}

// NewServer creates a new Chimney relay server.
func NewServer(config *Config, logger *slog.Logger) (*Server, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Load whitelist
	whitelistMgr, err := whitelist.LoadManager(config.IntentFile, config.EnforceFile)
	if err != nil {
		logger.Warn("failed to load whitelist, using empty", "error", err)
		whitelistMgr = whitelist.NewManager(whitelist.NewIntentLayer(), whitelist.NewEnforceLayer())
	}

	// Create user store for authentication.
	// Priority: Users (explicit PSK map) > UserIDs (UUID-derived PSK) > PSK (single-user).
	var userStore *auth.UserStore
	switch {
	case len(config.Users) > 0:
		userStore, err = auth.NewUserStore(config.Users, config.TagLen)
	case len(config.UserIDs) > 0:
		userStore, err = auth.NewUserStoreFromIDs(config.UserIDs, config.TagLen)
	case config.PSK != "":
		userStore, err = auth.NewUserStore(map[string]string{"default": config.PSK}, config.TagLen)
	default:
		return nil, fmt.Errorf("relay: one of PSK, Users, or UserIDs must be configured")
	}
	if err != nil {
		return nil, fmt.Errorf("relay: failed to create user store: %w", err)
	}

	return &Server{
		config:       config,
		whitelistMgr: whitelistMgr,
		userStore:    userStore,
		stats:        &Stats{},
		logger:       logger,
	}, nil
}

// Start starts the relay server.
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

// Stop stops the relay server.
func (s *Server) Stop() error {
	s.closed.Store(true)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	return nil
}

// Stats returns current server statistics.
func (s *Server) Stats() *Stats {
	return s.stats
}

// acceptLoop accepts incoming connections.
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

// handleConnection handles a single client connection.
func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	logger := s.logger.With("remote", clientConn.RemoteAddr().String())
	logger.Debug("new connection")

	// Step 1: Read ClientHello and extract SNI + ClientRandom
	clientHello, sni, clientRandom, err := s.readClientHello(clientConn)
	if err != nil {
		logger.Debug("failed to read ClientHello", "error", err)
		s.passiveFallback(clientConn, nil, logger)
		return
	}

	logger = logger.With("sni", sni)

	// Step 2: Whitelist check (关卡A + 关卡B)
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

	// Step 3: Connect to real site and forward handshake
	siteConn, err := net.DialTimeout("tcp", net.JoinHostPort(destIP, "443"), s.config.HandshakeTimeout)
	if err != nil {
		logger.Debug("failed to connect to real site", "error", err, "dest_ip", destIP)
		s.passiveFallback(clientConn, nil, logger)
		return
	}
	defer siteConn.Close()

	// Forward ClientHello to real site
	if _, err := siteConn.Write(clientHello); err != nil {
		logger.Debug("failed to forward ClientHello", "error", err)
		s.passiveFallback(clientConn, siteConn, logger)
		return
	}

	// Step 4: Relay handshake and extract ServerRandom
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

	// Step 5: If no first app data was captured, forward transparently
	if len(firstAppData) == 0 {
		logger.Debug("no first app data captured, forwarding transparently")
		s.forwardToSite(clientConn, siteConn, nil, logger)
		return
	}

	// Step 6: Pre-swap heuristic check.
	// Auth frame is now: [key_hint (4)] [tag (tagLen)], so +4 for hint.
	expectedAuthRecordMin := 5 + 4 + auth.DefaultTagLen + len(h2engine.H2ConnectionPreface)
	if len(firstAppData) < expectedAuthRecordMin {
		logger.Debug("first app data too short for Chimney, forwarding transparently",
			"record_len", len(firstAppData),
		)
		s.forwardToSite(clientConn, siteConn, firstAppData, logger)
		return
	}

	// Step 7: Attempt swap. The auth tag is verified inside performSwap
	// after extracting the key_hint from the auth frame.
	s.stats.AuthenticatedSwaps.Add(1)
	logger.Info("attempting swap")

	if err := s.performSwap(clientConn, siteConn, sni, serverRandom, clientRandom, firstAppData, logger); err != nil {
		logger.Debug("swap failed", "error", err)
		s.stats.AuthFailures.Add(1)
		// performSwap's pre-check failed without consuming data from
		// clientConn — firstAppData is intact and can be forwarded.
		s.forwardToSite(clientConn, siteConn, firstAppData, logger)
		return
	}
}

// readClientHello reads the ClientHello from the client connection.
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

// relayHandshake relays the TLS handshake between client and real site,
// monitoring TLS record types to determine when the handshake ends.
//
// It forwards all handshake records (0x16) and ChangeCipherSpec (0x14)
// bidirectionally. When the first Application Data record (0x17) arrives
// from the client, it stops forwarding and returns the buffered record.
// The site connection remains alive — the caller decides whether to swap
// (Chimney mode) or continue transparent forwarding.
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

		// Server → Client: forward everything, extract ServerRandom
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

		// Client → Server: forward handshake records, intercept first 0x17
		go func() {
			defer wg.Done()
			buf := make([]byte, TCPBufferSize)
			recordBuf := make([]byte, 0, 65536)

			for {
				n, readErr := clientConn.Read(buf)
				if n > 0 {
					recordBuf = append(recordBuf, buf[:n]...)

					// Parse complete TLS records from the buffer
					for len(recordBuf) >= 5 {
						recordType := recordBuf[0]
						recordLen := int(recordBuf[3])<<8 | int(recordBuf[4])
						total := 5 + recordLen
						if len(recordBuf) < total {
							break
						}

						if recordType == 0x17 {
							// First app data -- capture it AND all trailing data.
							// uTLS may send post-handshake 0x17 records before
							// the ChimneyRecord. Drain everything that follows.
							fa = make([]byte, len(recordBuf))
							copy(fa, recordBuf)
							recordBuf = recordBuf[:0]
							close(quit)
							siteConn.SetReadDeadline(time.Now())

							// Drain remaining data after the first 0x17
							clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
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
							return
						}

						// Forward handshake/CCS record to site
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

		// Clear any deadlines set during shutdown
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

// forwardToSite continues forwarding traffic to the real site.
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

// prependConn wraps a net.Conn with a data prefix prepended to reads.
// Used to re-inject data that was already consumed from the connection.
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

// remainingPrefix returns the portion of the prefix not yet read.
func (c *prependConn) remainingPrefix() []byte {
	if c.prefixOff < len(c.prefix) {
		return c.prefix[c.prefixOff:]
	}
	return nil
}

// performSwap performs the swap operation after successful auth.
func (s *Server) performSwap(clientConn, siteConn net.Conn, sni string, serverRandom, clientRandom, firstAppData []byte, logger *slog.Logger) error {
	// siteConn is kept alive until auth verification succeeds.
	// If we return an error before the "swap complete" log, the caller
	// can fall back to transparent forwarding.

	deriver, err := keyderiv.NewDeriverFromHex(s.config.PSK)
	if err != nil {
		return fmt.Errorf("create deriver: %w", err)
	}

	sendKey, recvKey, err := deriver.DeriveDirectionalKeys(serverRandom, clientRandom)
	if err != nil {
		return fmt.Errorf("derive directional keys: %w", err)
	}
	sendNonceBase, err := deriver.DeriveNonceBase(serverRandom, clientRandom)
	if err != nil {
		return fmt.Errorf("derive send nonce base: %w", err)
	}
	recvNonceBase, err := deriver.DeriveNonceBase(clientRandom, serverRandom)
	if err != nil {
		return fmt.Errorf("derive recv nonce base: %w", err)
	}

	logger.Debug("directional keys derived (RELAY)",
		"sendKey", hex.EncodeToString(sendKey[:4]),
		"recvKey", hex.EncodeToString(recvKey[:4]),
		"sendNonce", hex.EncodeToString(sendNonceBase),
		"recvNonce", hex.EncodeToString(recvNonceBase),
	)
	// Swap key/nonce pairs for the relay:
	// Client's sendKey ("chimney-sess-send") encrypts client→relay, so relay
	// must use it as the opener (recv) key. Client's recvKey ("chimney-sess-recv")
	// decrypts relay→client, so relay must use it as the sealer (send) key.
	// Same logic applies to nonce bases (info order matters for derivation).
	codec, err := record.NewCodecWithDirectionalKeys(recvKey, recvNonceBase, sendKey, sendNonceBase)
	if err != nil {
		kSess, _ := deriver.DeriveSessionKey(serverRandom, clientRandom)
		nonceBase, _ := deriver.DeriveNonceBase(serverRandom, clientRandom)
		codec, err = record.NewCodec(kSess, nonceBase)
		if err != nil {
			return fmt.Errorf("create codec: %w", err)
		}
	}

	// Scan firstAppData for a valid ChimneyRecord.
	// uTLS may have sent post-handshake 0x17 records before the
	// ChimneyRecord, so we iterate through TLS records and test each.
	chimneyRecord, preludeRecords := findChimneyRecord(firstAppData, deriver, serverRandom, clientRandom, logger)

	// If not found yet, the ChimneyRecord may not have arrived yet
	// (the client does its own drain+encode before writing).
	// Read more from clientConn and retry.
	if chimneyRecord == nil && len(firstAppData) < 4096 {
		logger.Debug("ChimneyRecord not in initial buffer, reading more from client")
		clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		readBuf := make([]byte, TCPBufferSize)
		for i := 0; i < 3 && chimneyRecord == nil; i++ {
			n, rdErr := clientConn.Read(readBuf)
			if n > 0 {
				firstAppData = append(firstAppData, readBuf[:n]...)
				chimneyRecord, preludeRecords = findChimneyRecord(firstAppData, deriver, serverRandom, clientRandom, logger)
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

	// Forward any prelude (non-Chimney) records to the real site.
	if len(preludeRecords) > 0 {
		logger.Debug("forwarding prelude records to site", "bytes", len(preludeRecords))
		if _, err := siteConn.Write(preludeRecords); err != nil {
			logger.Debug("failed to forward prelude records", "error", err)
		}
	}

	logger.Debug("pre-check: found valid ChimneyRecord", "offset", len(preludeRecords), "len", len(chimneyRecord))

	// Create a fresh codec for actual I/O (nonce starts at 0).
	// The previous codec was only used for scanning.
	codec, err = record.NewCodecWithDirectionalKeys(recvKey, recvNonceBase, sendKey, sendNonceBase)
	if err != nil {
		kSess, _ := deriver.DeriveSessionKey(serverRandom, clientRandom)
		nonceBase, _ := deriver.DeriveNonceBase(serverRandom, clientRandom)
		codec, err = record.NewCodec(kSess, nonceBase)
		if err != nil {
			return fmt.Errorf("create codec: %w", err)
		}
	}

	// Wrap clientConn with only the ChimneyRecord as prefix.
	wrappedReader := &prependConn{Conn: clientConn, prefix: chimneyRecord}
	recReader := record.NewRecordReader(wrappedReader, codec)
	recWriter := record.NewRecordWriter(wrappedReader, codec)

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

	// Complete H2 handshake: read client's SETTINGS ACK (sent by
	// completeH2Handshake before the auth tag). The client sends:
	//   1. Preface + SETTINGS  (consumed by AcceptAsServer)
	//   2. SETTINGS ACK
	//   3. Auth tag DATA frame
	// We must consume the ACK before reading the auth tag.
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

	// Auth verified — now it's safe to cut the real site connection.
	siteConn.Close()
	logger.Info("swap complete, H2 tunnel established")

	return s.handleTunnel(h2Eng, logger)
}

// tunnelConnPool manages backend connections for tunneled streams.
type tunnelConnPool struct {
	mu      sync.Mutex
	streams map[uint32]net.Conn
	dest    string
}

func newTunnelConnPool() *tunnelConnPool {
	return &tunnelConnPool{
		streams: make(map[uint32]net.Conn),
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
	defer p.mu.Unlock()

	conn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial backend %s: %w", dest, err)
	}
	p.streams[streamID] = conn
	return conn, nil
}

func (p *tunnelConnPool) closeStream(streamID uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if conn, ok := p.streams[streamID]; ok {
		conn.Close()
		delete(p.streams, streamID)
	}
}

func (p *tunnelConnPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for id, conn := range p.streams {
		conn.Close()
		delete(p.streams, id)
	}
}

// handleTunnel handles the H2 tunnel after swap with traffic profile pacing.
func (s *Server) handleTunnel(h2Eng *h2engine.Engine, logger *slog.Logger) error {
	pool := newTunnelConnPool()
	defer pool.closeAll()

	var trafficProfile *profile.Model
	if s.config.EnableProfiling {
		trafficProfile = profile.DefaultModel()
	}

	for {
		fh, payload, err := h2Eng.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				logger.Debug("tunnel closed by client")
				return nil
			}
			logger.Debug("frame read error", "error", err)
			return err
		}

		// Discard reserved-stream frames (padding, dilution) — they exist only
		// to maintain traffic shape and are not part of tunnel data.
		if h2engine.IsReservedStream(fh.StreamID) {
			continue
		}

		switch fh.Type {
		case h2engine.FrameData:
			if payload == nil || len(payload) < 2 {
				continue
			}
			cmd := payload[0]
			cmdData := payload[1:]

			switch cmd {
			case 0x01: // CONNECT
				dest := string(cmdData)
				logger.Debug("CONNECT", "stream_id", fh.StreamID, "dest", dest)
				backendConn, err := pool.createForStream(fh.StreamID, dest)
				if err != nil {
					logger.Debug("backend connect failed", "error", err)
					rstFrame := h2engine.RSTStreamFrame(fh.StreamID, h2engine.H2ErrRefusedStream)
					h2Eng.WriteRawFrame(rstFrame)
					continue
				}
				if err := h2Eng.WriteData(fh.StreamID, []byte{0x01}, false); err != nil {
					logger.Debug("failed to send CONNECT_OK", "error", err)
				}
				go s.readBackend(fh.StreamID, backendConn, h2Eng, logger)

			case 0x02: // DATA
				backendConn, err := pool.getOrCreate(fh.StreamID)
				if err != nil {
					logger.Debug("no backend for stream", "stream_id", fh.StreamID)
					continue
				}
				if _, err := backendConn.Write(cmdData); err != nil {
					logger.Debug("backend write failed", "error", err)
					pool.closeStream(fh.StreamID)
				}

			case 0x03: // CLOSE
				logger.Debug("CLOSE stream", "stream_id", fh.StreamID)
				pool.closeStream(fh.StreamID)
			}

		case h2engine.FrameWindowUpdate:
		case h2engine.FrameRSTStream:
			logger.Debug("RST_STREAM", "stream_id", fh.StreamID)
			pool.closeStream(fh.StreamID)

		case h2engine.FrameGoAway:
			logger.Debug("GOAWAY received")
			return nil
		}

		if trafficProfile != nil {
			delay := trafficProfile.RecordDelay()
			time.Sleep(delay)
		}
	}
}

// readBackend reads from a backend connection and sends data back as H2 DATA frames.
func (s *Server) readBackend(streamID uint32, backendConn net.Conn, h2Eng *h2engine.Engine, logger *slog.Logger) {
	buf := make([]byte, 32*1024)
	for {
		n, err := backendConn.Read(buf)
		if n > 0 {
			response := make([]byte, 1+n)
			response[0] = 0x02
			copy(response[1:], buf[:n])

			if werr := h2Eng.WriteData(streamID, response, false); werr != nil {
				logger.Debug("backend response write failed", "error", werr, "stream_id", streamID)
				return
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

// applySettingsSnapshot applies captured H2 SETTINGS from a site entry to engine settings.
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

// passiveFallback handles failed whitelist/auth checks.
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

// resolveDestination resolves an SNI to an IP address.
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

// extractSNI extracts the Server Name Indication from a ClientHello message.
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

// findChimneyRecord scans a concatenated buffer of TLS records for a valid
// ChimneyRecord. It iterates through each TLS record, and for each 0x17
// (application_data) record, creates a fresh codec and attempts decryption.
// The first record that decrypts successfully is returned as the chimneyRecord.
// All records before it (including non-Chimney 0x17 records, e.g. uTLS
// post-handshake) are returned as preludeRecords for forwarding to the real site.
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

// NewDeriverFromHexOrRaw creates a deriver that handles both hex and raw PSK.
func NewDeriverFromHexOrRaw(psk string) *keyderiv.Deriver {
	if d, err := keyderiv.NewDeriverFromHex(psk); err == nil {
		return d
	}
	return keyderiv.NewDeriver([]byte(psk))
}
