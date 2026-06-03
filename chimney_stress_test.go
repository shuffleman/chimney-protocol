//go:build stress

package chimney

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	stressSNI    = "cloudflare.com"
	stressUserID = "stress-test-00000000-0000-0000-0000-000000000001"
)

func TestLocalMixedTrafficStress(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test skipped in short mode")
	}

	backendAddr, stopBackend := startStressBackend(t)
	defer stopBackend()

	relayAddr := freeTCPAddr(t)
	relayServer, err := NewRelayServer(&RelayConfig{
		ListenAddr:  relayAddr,
		UserIDs:     []string{stressUserID},
		TagLen:      16,
		IntentYAML:  "version: 1\nentries:\n  cloudflare.com:\n    sni: cloudflare.com\n    settings_snapshot:\n      HEADER_TABLE_SIZE: 4096\n      ENABLE_PUSH: 0\n      MAX_CONCURRENT_STREAMS: 100\n      INITIAL_WINDOW_SIZE: 65535\n      MAX_FRAME_SIZE: 16384\n      MAX_HEADER_LIST_SIZE: 16384\n",
		EnforceYAML: "version: 1\nentries:\n  - cidr: \"0.0.0.0/0\"\n    provider: testing\n",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("create relay: %v", err)
	}
	go func() {
		if err := relayServer.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Errorf("relay start: %v", err)
		}
	}()
	defer relayServer.Stop()
	time.Sleep(200 * time.Millisecond)

	dialer, err := NewDialer(Config{
		RelayAddr:        relayAddr,
		SNI:              stressSNI,
		UserID:           stressUserID,
		TagLen:           16,
		Fingerprint:      "chrome",
		ConnectTimeout:   10 * time.Second,
		HandshakeTimeout: 10 * time.Second,
		PoolSize:         8,
		TCPBufferSize:    256 * 1024,
	})
	if err != nil {
		t.Fatalf("create dialer: %v", err)
	}
	defer dialer.Close()

	const (
		downloadWorkers = 12
		uploadWorkers   = 12
		bytesPerWorker  = 8 * 1024 * 1024
	)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var dlBytes atomic.Int64
	var ulBytes atomic.Int64
	var errCount atomic.Int64
	errCh := make(chan error, downloadWorkers+uploadWorkers)

	start := time.Now()
	for i := 0; i < downloadWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			n, err := runStressDownload(ctx, dialer, backendAddr, bytesPerWorker)
			dlBytes.Add(n)
			if err != nil {
				errCount.Add(1)
				errCh <- fmt.Errorf("download worker %d: %w", id, err)
			}
		}(i)
	}
	for i := 0; i < uploadWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			n, err := runStressUpload(ctx, dialer, backendAddr, bytesPerWorker)
			ulBytes.Add(n)
			if err != nil {
				errCount.Add(1)
				errCh <- fmt.Errorf("upload worker %d: %w", id, err)
			}
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("stress timed out after %s: dl=%d ul=%d diagnostics:\n%s",
			time.Since(start).Round(time.Millisecond), dlBytes.Load(), ulBytes.Load(), dialer.Diagnostics())
	}
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}
	if got := errCount.Load(); got != 0 {
		t.Fatalf("stress finished with %d worker errors", got)
	}

	wantDL := int64(downloadWorkers * bytesPerWorker)
	wantUL := int64(uploadWorkers * bytesPerWorker)
	if dlBytes.Load() != wantDL {
		t.Fatalf("download bytes = %d, want %d", dlBytes.Load(), wantDL)
	}
	if ulBytes.Load() != wantUL {
		t.Fatalf("upload bytes = %d, want %d", ulBytes.Load(), wantUL)
	}

	t.Logf("stress ok: dl=%.1f MiB ul=%.1f MiB elapsed=%s",
		float64(dlBytes.Load())/1024/1024,
		float64(ulBytes.Load())/1024/1024,
		time.Since(start).Round(time.Millisecond))
}

func startStressBackend(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() { _ = ln.Close() })
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleStressBackendConn(conn)
		}
	}()

	return ln.Addr().String(), stop
}

func handleStressBackendConn(conn net.Conn) {
	defer conn.Close()
	cmd := make([]byte, 1)
	if _, err := io.ReadFull(conn, cmd); err != nil {
		return
	}
	switch cmd[0] {
	case 'D':
		block := bytes.Repeat([]byte("chimney-stress-download-block:"), 2048)
		for {
			if _, err := conn.Write(block); err != nil {
				return
			}
		}
	case 'U':
		_, _ = io.Copy(io.Discard, conn)
	default:
		return
	}
}

func runStressDownload(ctx context.Context, dialer *Dialer, backendAddr string, target int64) (int64, error) {
	conn, err := dialer.DialContext(ctx, "tcp", backendAddr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{'D'}); err != nil {
		return 0, err
	}

	buf := make([]byte, 128*1024)
	var read int64
	for read < target {
		if err := ctx.Err(); err != nil {
			return read, err
		}
		n, err := conn.Read(buf)
		if n > 0 {
			remaining := target - read
			if int64(n) > remaining {
				n = int(remaining)
			}
			read += int64(n)
		}
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func runStressUpload(ctx context.Context, dialer *Dialer, backendAddr string, target int64) (int64, error) {
	conn, err := dialer.DialContext(ctx, "tcp", backendAddr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{'U'}); err != nil {
		return 0, err
	}

	buf := make([]byte, 128*1024)
	if _, err := rand.Read(buf); err != nil {
		return 0, err
	}
	var written int64
	for written < target {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		toWrite := len(buf)
		if remaining := int(target - written); remaining < toWrite {
			toWrite = remaining
		}
		n, err := conn.Write(buf[:toWrite])
		if n > 0 {
			written += int64(n)
		}
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free addr listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("free addr close: %v", err)
	}
	return addr
}
