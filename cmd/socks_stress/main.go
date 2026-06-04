// socks_stress drives mixed upload/download traffic through a SOCKS5 proxy.
//
// It starts a local TCP backend, then opens many SOCKS5 CONNECT streams to
// that backend. Use it with real chimney-client and chimney-relay binaries.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var (
	socksAddr       = flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy address")
	downloadWorkers = flag.Int("dl", 12, "download workers")
	uploadWorkers   = flag.Int("ul", 12, "upload workers")
	workerBytes     = flag.Int64("bytes", 8*1024*1024, "bytes per worker")
	timeout         = flag.Duration("timeout", 90*time.Second, "overall timeout")
	bufferSize      = flag.Int("buf", 128*1024, "I/O buffer size")
	jsonOutput      = flag.Bool("json", false, "emit a machine-readable JSON result")
)

type stats struct {
	dlBytes atomic.Int64
	ulBytes atomic.Int64
	errors  atomic.Int64
}

func main() {
	flag.Parse()

	backendAddr, stopBackend, err := startBackend()
	if err != nil {
		log.Fatalf("backend: %v", err)
	}
	defer stopBackend()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var wg sync.WaitGroup
	var s stats
	errCh := make(chan error, *downloadWorkers+*uploadWorkers)
	start := time.Now()

	for i := 0; i < *downloadWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			n, err := download(ctx, *socksAddr, backendAddr, *workerBytes, *bufferSize)
			s.dlBytes.Add(n)
			if err != nil {
				s.errors.Add(1)
				errCh <- fmt.Errorf("download %d: %w", id, err)
			}
		}(i)
	}

	for i := 0; i < *uploadWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			n, err := upload(ctx, *socksAddr, backendAddr, *workerBytes, *bufferSize)
			s.ulBytes.Add(n)
			if err != nil {
				s.errors.Add(1)
				errCh <- fmt.Errorf("upload %d: %w", id, err)
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
		log.Fatalf("timeout: dl=%d ul=%d errors=%d", s.dlBytes.Load(), s.ulBytes.Load(), s.errors.Load())
	}
	close(errCh)

	for err := range errCh {
		log.Print(err)
	}

	elapsed := time.Since(start)
	totalBytes := s.dlBytes.Load() + s.ulBytes.Load()
	mbps := float64(totalBytes) * 8 / elapsed.Seconds() / 1e6
	result := stressResult{
		BackendAddr:     backendAddr,
		SocksAddr:       *socksAddr,
		DownloadWorkers: *downloadWorkers,
		UploadWorkers:   *uploadWorkers,
		BytesPerWorker:  *workerBytes,
		DownloadBytes:   s.dlBytes.Load(),
		UploadBytes:     s.ulBytes.Load(),
		Errors:          s.errors.Load(),
		ElapsedMillis:   elapsed.Milliseconds(),
		AverageMbps:     mbps,
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			log.Fatalf("encode result: %v", err)
		}
	} else {
		fmt.Printf("Backend: %s\n", backendAddr)
		fmt.Printf("SOCKS5:  %s\n", *socksAddr)
		fmt.Printf("Workers: dl=%d ul=%d bytes_per_worker=%d\n", *downloadWorkers, *uploadWorkers, *workerBytes)
		fmt.Printf("Result:  dl=%.1f MiB ul=%.1f MiB errors=%d elapsed=%s avg=%.1f Mbps\n",
			float64(result.DownloadBytes)/1024/1024,
			float64(result.UploadBytes)/1024/1024,
			result.Errors,
			elapsed.Round(time.Millisecond),
			result.AverageMbps,
		)
	}

	if s.errors.Load() != 0 {
		log.Fatalf("stress failed with %d errors", s.errors.Load())
	}
}

type stressResult struct {
	BackendAddr     string  `json:"backend_addr"`
	SocksAddr       string  `json:"socks_addr"`
	DownloadWorkers int     `json:"download_workers"`
	UploadWorkers   int     `json:"upload_workers"`
	BytesPerWorker  int64   `json:"bytes_per_worker"`
	DownloadBytes   int64   `json:"download_bytes"`
	UploadBytes     int64   `json:"upload_bytes"`
	Errors          int64   `json:"errors"`
	ElapsedMillis   int64   `json:"elapsed_millis"`
	AverageMbps     float64 `json:"average_mbps"`
}

func startBackend() (addr string, stop func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	var once sync.Once
	stop = func() {
		once.Do(func() { _ = ln.Close() })
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleBackend(conn)
		}
	}()

	return ln.Addr().String(), stop, nil
}

func handleBackend(conn net.Conn) {
	defer conn.Close()
	cmd := make([]byte, 1)
	if _, err := io.ReadFull(conn, cmd); err != nil {
		return
	}
	lenBuf := make([]byte, 8)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return
	}
	targetBytes := int64(binary.BigEndian.Uint64(lenBuf))

	switch cmd[0] {
	case 'D':
		buf := make([]byte, *bufferSize)
		var written int64
		for written < targetBytes {
			n := len(buf)
			if remaining := int(targetBytes - written); remaining < n {
				n = remaining
			}
			fillPattern(buf[:n], written)
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
			written += int64(n)
		}
	case 'U':
		buf := make([]byte, *bufferSize)
		var read int64
		for read < targetBytes {
			n := len(buf)
			if remaining := int(targetBytes - read); remaining < n {
				n = remaining
			}
			if _, err := io.ReadFull(conn, buf[:n]); err != nil {
				return
			}
			if !verifyPattern(buf[:n], read) {
				_, _ = conn.Write([]byte{'E'})
				return
			}
			read += int64(n)
		}
		_, _ = conn.Write([]byte{'K'})
	}
}

func download(ctx context.Context, socks, target string, targetBytes int64, bufsz int) (int64, error) {
	conn, err := socksConnect(ctx, socks, target)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{'D'}); err != nil {
		return 0, err
	}
	if err := writeLength(conn, targetBytes); err != nil {
		return 0, err
	}

	buf := make([]byte, bufsz)
	var read int64
	for read < targetBytes {
		if err := ctx.Err(); err != nil {
			return read, err
		}
		n, err := conn.Read(buf)
		if n > 0 {
			remaining := targetBytes - read
			if int64(n) > remaining {
				n = int(remaining)
			}
			if !verifyPattern(buf[:n], read) {
				return read, fmt.Errorf("download data mismatch at offset %d", read)
			}
			read += int64(n)
		}
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func upload(ctx context.Context, socks, target string, targetBytes int64, bufsz int) (int64, error) {
	conn, err := socksConnect(ctx, socks, target)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{'U'}); err != nil {
		return 0, err
	}
	if err := writeLength(conn, targetBytes); err != nil {
		return 0, err
	}

	buf := make([]byte, bufsz)

	var written int64
	for written < targetBytes {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		toWrite := len(buf)
		if remaining := int(targetBytes - written); remaining < toWrite {
			toWrite = remaining
		}
		fillPattern(buf[:toWrite], written)
		n, err := conn.Write(buf[:toWrite])
		if n > 0 {
			written += int64(n)
		}
		if err != nil {
			return written, err
		}
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return written, fmt.Errorf("upload ack: %w", err)
	}
	if ack[0] != 'K' {
		return written, fmt.Errorf("upload backend verification failed: 0x%02x", ack[0])
	}
	return written, nil
}

func writeLength(conn net.Conn, n int64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(n))
	_, err := conn.Write(buf[:])
	return err
}

func fillPattern(buf []byte, offset int64) {
	for i := range buf {
		buf[i] = patternByte(offset + int64(i))
	}
}

func verifyPattern(buf []byte, offset int64) bool {
	for i, b := range buf {
		if b != patternByte(offset+int64(i)) {
			return false
		}
	}
	return true
}

func patternByte(offset int64) byte {
	return byte((offset*31 + 17) % 251)
}

func socksConnect(ctx context.Context, socks, target string) (net.Conn, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", socks)
	if err != nil {
		return nil, fmt.Errorf("dial socks: %w", err)
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks greeting: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks greeting reply: %w", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks auth reply = %x", reply)
	}

	req, err := socksRequest(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks connect: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks connect reply: %w", err)
	}
	if header[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks connect failed: code=0x%02x", header[1])
	}

	if err := drainSocksBindAddr(conn, header[3]); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func socksRequest(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("target address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("target port: %q", portText)
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("domain too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	req = append(req, portBuf[:]...)
	return req, nil
}

func drainSocksBindAddr(conn net.Conn, atyp byte) error {
	var n int
	switch atyp {
	case 0x01:
		n = 4
	case 0x04:
		n = 16
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("socks bind domain len: %w", err)
		}
		n = int(lenBuf[0])
	default:
		return fmt.Errorf("unsupported socks reply address type: 0x%02x", atyp)
	}

	if n > 0 {
		if _, err := io.ReadFull(conn, make([]byte, n)); err != nil {
			return fmt.Errorf("socks bind addr: %w", err)
		}
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		return fmt.Errorf("socks bind port: %w", err)
	}
	return nil
}
