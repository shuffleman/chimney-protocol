// upload_debug runs a local relay + client and performs concurrent uploads,
// capturing both sides' record trails when a bad record MAC occurs.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"strings"

	"log/slog"

	chimney "github.com/shuffleman/chimney-protocol"
	"github.com/shuffleman/chimney-protocol/internal/record"
)

// tracedOp records one seal/open operation for post-mortem comparison.
type tracedOp struct {
	dir         string // "seal" or "open" or "open-ERR"
	seq         uint64
	nonce       string // hex
	hdr         string // hex (5 bytes)
	plainFP     string // hex (first 4 bytes of plaintext, or empty for errors)
	plainHash   string // hex (SHA256 of full plaintext)
	ctxtFP      string // hex (first 8 bytes of ciphertext)
	ctxtHash    string // hex (SHA256 of full ciphertext)
	ctxtPreview string // hex (first 64 bytes of ciphertext)
	keyFP       string // hex (4 bytes, first 4 bytes of SHA256(key))
}

// traceCollector gathers seal/open ops from both sides in a single process.
type traceCollector struct {
	mu         sync.Mutex
	ops        []tracedOp
	openErrCnt int
	sealCnt    int
	openCnt    int
	sealFull   map[uint64][]byte // seq -> full ciphertext (for byte-level comparison)
	encodeRecs map[string][]byte // "keyFP:seq" -> full record bytes (from EncodeRecord)
	decodeRecs map[string][]byte // "keyFP:seq" -> full record bytes (from DecodeRecord)
}

func (tc *traceCollector) recordTrace(dir string, seq uint64, recordData []byte, keyFP [4]byte) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	keyID := hex.EncodeToString(keyFP[:]) + ":" + fmt.Sprintf("%d", seq)
	if dir == "encode" {
		if tc.encodeRecs == nil {
			tc.encodeRecs = make(map[string][]byte)
		}
		cp := make([]byte, len(recordData))
		copy(cp, recordData)
		tc.encodeRecs[keyID] = cp
	} else if dir == "decode" {
		if tc.decodeRecs == nil {
			tc.decodeRecs = make(map[string][]byte)
		}
		cp := make([]byte, len(recordData))
		copy(cp, recordData)
		tc.decodeRecs[keyID] = cp
		// Compare with encode only when the same keyFP:seq exists
		if encRec, ok := tc.encodeRecs[keyID]; ok {
			if len(encRec) != len(cp) {
				log.Printf("!!! RECORD MISMATCH %s: len(encode)=%d len(decode)=%d", keyID, len(encRec), len(cp))
				minLen := len(encRec)
				if len(cp) < minLen {
					minLen = len(cp)
				}
				tailCtx := 32
				encTail := encRec[minLen-tailCtx:]
				decTail := cp[minLen-tailCtx:]
				log.Printf("!!! LEN_MISMATCH ENC tail[%d:]=%x", minLen-tailCtx, encTail)
				log.Printf("!!! LEN_MISMATCH DEC tail[%d:]=%x", minLen-tailCtx, decTail)
			} else {
				firstDiff := -1
				lastDiff := -1
				totalDiffs := 0
				for i := 0; i < len(cp); i++ {
					if encRec[i] != cp[i] {
						if firstDiff < 0 {
							firstDiff = i
						}
						lastDiff = i
						totalDiffs++
					}
				}
				if firstDiff >= 0 {
					allDiffer := totalDiffs == len(cp)-firstDiff
					log.Printf("!!! RECORD BYTE MISMATCH %s: first_diff_at=%d last_diff_at=%d total_diffs=%d total_len=%d all_after_differ=%v",
						keyID, firstDiff, lastDiff, totalDiffs, len(cp), allDiffer)
					ctx := 16
					start := firstDiff - ctx
					if start < 0 {
						start = 0
					}
					end := firstDiff + ctx
					if end > len(cp) {
						end = len(cp)
					}
					log.Printf("!!! ENC[%d:%d]=%x", start, end, encRec[start:end])
					log.Printf("!!! DEC[%d:%d]=%x", start, end, cp[start:end])
					tailCtx := 32
					tailStart := len(cp) - tailCtx
					log.Printf("!!! ENC tail[%d:]=%x", tailStart, encRec[tailStart:])
					log.Printf("!!! DEC tail[%d:]=%x", tailStart, cp[tailStart:])
					encHash := sha256.Sum256(encRec)
					decHash := sha256.Sum256(cp)
					log.Printf("!!! ENC SHA256=%s", hex.EncodeToString(encHash[:]))
					log.Printf("!!! DEC SHA256=%s", hex.EncodeToString(decHash[:]))
				}
			}
		}
	}
}

func (tc *traceCollector) add(dir string, seq uint64, nonce, hdr, plaintext, ciphertext []byte, keyFP [4]byte) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	hdrHex := hex.EncodeToString(hdr)
	nonceHex := hex.EncodeToString(nonce)
	var fpHex string
	var plainHashHex string
	if len(plaintext) >= 4 {
		fpHex = hex.EncodeToString(plaintext[:4])
	}
	if len(plaintext) > 0 {
		h := sha256.Sum256(plaintext)
		plainHashHex = hex.EncodeToString(h[:])
	}
	var ctxtFp string
	if len(ciphertext) >= 8 {
		ctxtFp = hex.EncodeToString(ciphertext[:8])
	}
	keyFPHex := hex.EncodeToString(keyFP[:])
	var ctxtHashHex string
	var ctxtPreviewHex string
	if len(ciphertext) > 0 {
		h := sha256.Sum256(ciphertext)
		ctxtHashHex = hex.EncodeToString(h[:])
		previewLen := len(ciphertext)
		if previewLen > 64 {
			previewLen = 64
		}
		ctxtPreviewHex = hex.EncodeToString(ciphertext[:previewLen])
	}
	tc.ops = append(tc.ops, tracedOp{
		dir: dir, seq: seq, nonce: nonceHex, hdr: hdrHex, plainFP: fpHex, plainHash: plainHashHex, ctxtFP: ctxtFp, ctxtHash: ctxtHashHex, ctxtPreview: ctxtPreviewHex, keyFP: keyFPHex,
	})
	if dir == "open-ERR" {
		log.Printf("!!! stored open-ERR at ops[%d] seq=%d", len(tc.ops)-1, seq)
	}
	switch dir {
	case "seal":
		tc.sealCnt++
		if tc.sealFull == nil {
			tc.sealFull = make(map[uint64][]byte)
		}
		full := make([]byte, len(ciphertext))
		copy(full, ciphertext)
		tc.sealFull[seq] = full
	case "open":
		tc.openCnt++
	case "open-ERR":
		tc.openErrCnt++
		log.Printf("!!! open-ERR captured: seq=%d nonce=%s hdr=%s ctxtFP=%s",
			seq, nonceHex, hdrHex, ctxtFp)
		// Byte-by-byte comparison with corresponding seal
		if sealCtxt, ok := tc.sealFull[seq]; ok {
			mismatches := 0
			firstMismatch := -1
			minLen := len(sealCtxt)
			if len(ciphertext) < minLen {
				minLen = len(ciphertext)
			}
			for i := 0; i < minLen; i++ {
				if sealCtxt[i] != ciphertext[i] {
					if mismatches == 0 {
						firstMismatch = i
					}
					mismatches++
				}
			}
			if mismatches > 0 {
				log.Printf("!!! BYTE MISMATCH: seq=%d len(seal)=%d len(open)=%d first_diff_at=%d total_diffs=%d",
					seq, len(sealCtxt), len(ciphertext), firstMismatch, mismatches)
				ctx := 16
				start := firstMismatch - ctx
				if start < 0 {
					start = 0
				}
				end := firstMismatch + ctx
				if end > minLen {
					end = minLen
				}
				log.Printf("!!! SEAL[%d:%d]=%x", start, end, sealCtxt[start:end])
				log.Printf("!!! OPEN[%d:%d]=%x", start, end, ciphertext[start:end])
			} else {
				log.Printf("!!! SAME CIPHERTEXT but decryption failed! seq=%d len=%d", seq, len(ciphertext))
			}
		} else {
			log.Printf("!!! NO matching seal found for seq=%d", seq)
		}
	default:
		log.Printf("!!! UNKNOWN dir=%q seq=%d", dir, seq)
	}
}

func (tc *traceCollector) dumpMismatch(relayFailSeq uint64) string {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "=== Trace comparison around seq %d ===\n", relayFailSeq)

	// Separate seal and open ops
	type opPair struct{ seal, open *tracedOp }
	bySeq := make(map[uint64]*opPair)
	for i := range tc.ops {
		op := &tc.ops[i]
		if bySeq[op.seq] == nil {
			bySeq[op.seq] = &opPair{}
		}
		switch op.dir {
		case "seal":
			bySeq[op.seq].seal = op
		case "open", "open-ERR":
			bySeq[op.seq].open = op
		}
	}

	// Show the last N sequences around the failure.
	start := int64(relayFailSeq) - 10
	if start < 0 {
		start = 0
	}
	for seq := uint64(start); seq <= relayFailSeq+5; seq++ {
		pair := bySeq[seq]
		if pair == nil {
			continue
		}
		sealStr := "(none)"
		openStr := "(none)"
		if pair.seal != nil {
			sealStr = fmt.Sprintf("fp=%s phash=%s ctxt=%s hash=%s nonce=%s hdr=%s key=%s", pair.seal.plainFP, pair.seal.plainHash[:16], pair.seal.ctxtFP, pair.seal.ctxtHash[:16], pair.seal.nonce, pair.seal.hdr, pair.seal.keyFP)
		}
		if pair.open != nil {
			openStr = pair.open.dir
			if pair.open.plainFP != "" {
				openStr += fmt.Sprintf(" fp=%s phash=%s", pair.open.plainFP, pair.open.plainHash[:16])
			}
			openStr += fmt.Sprintf(" ctxt=%s hash=%s nonce=%s hdr=%s key=%s", pair.open.ctxtFP, pair.open.ctxtHash[:16], pair.open.nonce, pair.open.hdr, pair.open.keyFP)
		}
		fmt.Fprintf(&b, "seq=%d  SEAL: %s\n", seq, sealStr)
		fmt.Fprintf(&b, "         OPEN: %s\n", openStr)
		if pair.seal != nil && pair.open != nil && pair.open.plainHash != "" && pair.seal.plainHash != pair.open.plainHash {
			fmt.Fprintf(&b, "  *** PLAINTEXT MISMATCH: seal phash=%s != open phash=%s\n", pair.seal.plainHash[:32], pair.open.plainHash[:32])
		}
	}
	return b.String()
}

func main() {
	collector := &traceCollector{}

	// Install a DebugTracer that captures every seal/open operation.
	record.DebugTracer = func(dir string, seq uint64, nonce, hdr, plaintext, ciphertext []byte, keyFP [4]byte) {
		collector.add(dir, seq, nonce, hdr, plaintext, ciphertext, keyFP)
	}
	// Install a RecordTraceHook that captures full record bytes from both sides.
	// keyFP distinguishes client→relay (sendKey) from relay→client (recvKey) directions.
	record.RecordTraceHook = func(dir string, seq uint64, recordData []byte, keyFP [4]byte) {
		collector.recordTrace(dir, seq, recordData, keyFP)
	}

	// PSK used by both sides.
	psk := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	userID := "default"
	tagLen := 16

	// Start a discard backend server.
	discardLn, err := net.Listen("tcp", "127.0.0.1:19999")
	if err != nil {
		log.Fatal("discard listen:", err)
	}
	go func() {
		for {
			conn, err := discardLn.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(io.Discard, conn)
				conn.Close()
			}()
		}
	}()
	log.Println("Discard backend on :19999")

	// Start the relay.
	relayCfg := &chimney.RelayConfig{
		ListenAddr:  "127.0.0.1:19443",
		PSK:         psk,
		TagLen:      tagLen,
		IntentYAML:  "version: 1\nentries:\n  cloudflare.com:\n    sni: cloudflare.com\n    settings_snapshot:\n      HEADER_TABLE_SIZE: 4096\n      ENABLE_PUSH: 0\n      MAX_CONCURRENT_STREAMS: 100\n      INITIAL_WINDOW_SIZE: 65535\n      MAX_FRAME_SIZE: 16384\n      MAX_HEADER_LIST_SIZE: 16384\n",
		EnforceYAML: "version: 1\nentries:\n  - cidr: \"0.0.0.0/0\"\n    provider: testing\n",
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	relayServer, err := chimney.NewRelayServer(relayCfg, logger)
	if err != nil {
		log.Fatal("create relay:", err)
	}
	go func() {
		if err := relayServer.Start(); err != nil {
			log.Fatal("relay start:", err)
		}
	}()
	defer relayServer.Stop()
	time.Sleep(200 * time.Millisecond)
	log.Println("Relay on :19443")

	// Start the client.
	clientCfg := chimney.Config{
		RelayAddr:        "127.0.0.1:19443",
		SNI:              "cloudflare.com",
		PSK:              psk,
		UserID:           userID,
		TagLen:           tagLen,
		Fingerprint:      "chrome",
		ConnectTimeout:   10 * time.Second,
		HandshakeTimeout: 10 * time.Second,
		PoolSize:         4, // Match speedtest pool_size
	}

	dialer, err := chimney.NewDialer(clientCfg)
	if err != nil {
		log.Fatal("create dialer:", err)
	}
	defer dialer.Close()
	log.Println("Client dialer created")

	// Run concurrent uploads to reproduce the 8-stream issue.
	const numUploads = 8
	const uploadSize = 20 * 1024 * 1024
	const targetAddr = "127.0.0.1:19999"

	var wg sync.WaitGroup
	var totalBytes atomic.Int64
	var errCount atomic.Int64
	var badMACCount atomic.Int64
	var firstErrorMsg atomic.Value

	// Background goroutine to periodically dump client diagnostics.
	stopDiag := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				diag := dialer.Diagnostics()
				if diag != "" {
					log.Printf("=== Periodic client diagnostics ===\n%s", diag)
				}
			case <-stopDiag:
				return
			}
		}
	}()

	for i := 0; i < numUploads; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialer.DialContext(context.Background(), "tcp", targetAddr)
			if err != nil {
				errCount.Add(1)
				log.Printf("U%d: dial error: %v", i, err)
				return
			}
			defer conn.Close()

			buf := make([]byte, 32*1024)
			rand.Read(buf)
			written := 0
			start := time.Now()
			for written < uploadSize {
				toWrite := len(buf)
				if toWrite > uploadSize-written {
					toWrite = uploadSize - written
				}
				n, err := conn.Write(buf[:toWrite])
				if err != nil {
					errCount.Add(1)
					msg := fmt.Sprintf("U%d: write error at %d/%d bytes (%.1fs): %v",
						i, written, uploadSize, time.Since(start).Seconds(), err)
					log.Print(msg)
					if firstErrorMsg.Load() == nil {
						firstErrorMsg.Store(msg)
					}
					if isBadRecordMAC(err.Error()) {
						badMACCount.Add(1)
					}
					return
				}
				written += n
				totalBytes.Add(int64(n))
			}
			log.Printf("U%d: completed %d bytes in %.1fs", i, written, time.Since(start).Seconds())
		}()
	}

	log.Printf("Started %d uploads of %d bytes each...", numUploads, uploadSize)

	// Wait with timeout since conn.Close() can block when tunnel is broken.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		log.Println("All uploads completed normally")
	case <-time.After(30 * time.Second):
		log.Println("TIMEOUT waiting for uploads — tunnel cleanup may be stuck")
	}
	close(stopDiag)

	log.Println("=== All done ===")
	log.Printf("Total bytes uploaded: %d", totalBytes.Load())
	log.Printf("Errors: %d, Bad record MAC: %d", errCount.Load(), badMACCount.Load())
	if firstMsg := firstErrorMsg.Load(); firstMsg != nil {
		log.Printf("First error: %s", firstMsg)
	}

	// Print final client-side diagnostics.
	log.Println("=== Final client diagnostics ===")
	log.Print(dialer.Diagnostics())

	log.Printf("=== Trace stats: seal=%d open=%d open-ERR=%d ===",
		collector.sealCnt, collector.openCnt, collector.openErrCnt)

	// Find the failure sequence from the trace.
	collector.mu.Lock()
	opsCopy := make([]tracedOp, len(collector.ops))
	copy(opsCopy, collector.ops)
	openErrCnt := collector.openErrCnt
	collector.mu.Unlock()

	var failSeq uint64
	for _, op := range opsCopy {
		if op.dir == "open-ERR" && op.seq > 0 {
			failSeq = op.seq
			break
		}
	}
	// Fallback: use first open-ERR even if seq=0 (pre-check)
	if failSeq == 0 {
		for _, op := range opsCopy {
			if op.dir == "open-ERR" {
				failSeq = op.seq
				break
			}
		}
	}
	if failSeq == 0 && openErrCnt > 0 {
		log.Printf("WARNING: openErrCnt=%d but no open-ERR entry found in ops (%d entries)!",
			openErrCnt, len(opsCopy))
		// Dump all dir values to debug
		for i, op := range opsCopy {
			if op.dir != "seal" && op.dir != "open" {
				log.Printf("  ops[%d] dir=%q seq=%d", i, op.dir, op.seq)
			}
		}
	}
	log.Printf("=== Trace comparison around failure seq=%d ===", failSeq)
	log.Print(collector.dumpMismatch(failSeq))

	if errCount.Load() > 0 {
		os.Exit(1)
	}
}

func isBadRecordMAC(s string) bool {
	return strings.Contains(s, "bad record MAC") || strings.Contains(s, "bad_record_mac")
}
