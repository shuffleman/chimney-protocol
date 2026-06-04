// tcp_page_test: 测试 chimney 特定的记录大小和修复验证。
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const numChunks = 500

func runTest(recSize int, port int, delay time.Duration) string {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Sprintf("listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	chunks := make([][]byte, numChunks)
	hashes := make([]string, numChunks)
	for i := range chunks {
		c := make([]byte, recSize)
		rand.Read(c)
		chunks[i] = c
		h := sha256.Sum256(c)
		hashes[i] = hex.EncodeToString(h[:8])
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 128*1024)
		totalExpected := numChunks * recSize
		allData := make([]byte, 0, totalExpected)

		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		for len(allData) < totalExpected {
			n, err := conn.Read(buf)
			if err != nil {
				if len(allData) < totalExpected {
					numComplete := len(allData) / recSize
					errors := 0
					firstDiff := -1
					for i := 0; i < numComplete; i++ {
						chunk := allData[i*recSize : (i+1)*recSize]
						h := sha256.Sum256(chunk)
						if hex.EncodeToString(h[:8]) != hashes[i] {
							if errors == 0 {
								for j := 0; j < len(chunk); j++ {
									if chunk[j] != chunks[i][j] {
										firstDiff = j
										break
									}
								}
							}
							errors++
						}
					}
					if errors > 0 {
						errCh <- fmt.Errorf("LOST+CORRUPT: %d/%d corrupt=%d diff=%d", len(allData), totalExpected, errors, firstDiff)
					} else {
						errCh <- fmt.Errorf("LOST: %d/%d (%.0f%%)", len(allData), totalExpected, float64(len(allData))*100/float64(totalExpected))
					}
				}
				return
			}
			allData = append(allData, buf[:n]...)
		}

		errors := 0
		firstDiff := -1
		for i := 0; i < numChunks; i++ {
			chunk := allData[i*recSize : (i+1)*recSize]
			h := sha256.Sum256(chunk)
			if hex.EncodeToString(h[:8]) != hashes[i] {
				if errors == 0 {
					for j := 0; j < len(chunk); j++ {
						if chunk[j] != chunks[i][j] {
							firstDiff = j
							break
						}
					}
				}
				errors++
			}
		}
		if errors > 0 {
			errCh <- fmt.Errorf("CORRUPT: %d/%d diff=%d", errors, numChunks, firstDiff)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		for _, chunk := range chunks {
			if _, err := conn.Write(chunk); err != nil {
				errCh <- fmt.Errorf("write: %w", err)
				return
			}
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}()

	wg.Wait()
	select {
	case err := <-errCh:
		if err == nil {
			return "PASS"
		}
		return err.Error()
	default:
		return "PASS"
	}
}

func main() {
	// Chimney 记录大小：
	// 记录 = 5 (TLS) + 9 (H2 头) + H2_payload + 16 (AEAD 标签) = 30 + H2_payload
	// H2_payload = 16384（当前）→ 记录 = 16414
	// H2_payload = 4066（建议）→ 记录 = 4096

	tests := []struct {
		size  int
		label string
	}{
		{4096, "4096 (1 page, H2=4066)"},
		{16414, "16414 (current, H2=16384)"},
		{8192, "8192 (2 pages, H2=8162)"},
	}

	log.Println("=== WITHOUT delay ===")
	for ti, t := range tests {
		pass := 0
		for i := 0; i < 5; i++ {
			port := 26000 + ti*10 + i
			r := runTest(t.size, port, 0)
			if r == "PASS" {
				pass++
			} else {
				log.Printf("  %s run %d: %s", t.label, i+1, r)
			}
		}
		log.Printf("%s: %d/5 PASS", t.label, pass)
	}

	log.Println("=== WITH 10µs delay ===")
	for ti, t := range tests {
		pass := 0
		for i := 0; i < 5; i++ {
			port := 27000 + ti*10 + i
			r := runTest(t.size, port, 10*time.Microsecond)
			if r == "PASS" {
				pass++
			} else {
				log.Printf("  %s run %d: %s", t.label, i+1, r)
			}
		}
		log.Printf("%s: %d/5 PASS", t.label, pass)
	}
}
