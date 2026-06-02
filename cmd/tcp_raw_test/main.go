// tcp_raw_test sends 16414-byte chunks over raw TCP and verifies them.
// This isolates whether the corruption is in the Windows TCP stack or in chimney.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const chunkSize = 16414
const numChunks = 500

func main() {
	// Server (receiver)
	ln, err := net.Listen("tcp", "127.0.0.1:19998")
	if err != nil {
		log.Fatal("listen:", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Generate predictable chunks
	chunks := make([][]byte, numChunks)
	hashes := make([]string, numChunks)
	for i := range chunks {
		c := make([]byte, chunkSize)
		rand.Read(c)
		chunks[i] = c
		h := sha256.Sum256(c)
		hashes[i] = hex.EncodeToString(h[:8])
	}

	// Receiver goroutine
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
		totalRead := 0
		totalExpected := numChunks * chunkSize
		allData := make([]byte, 0, totalExpected)

		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		for totalRead < totalExpected {
			n, err := conn.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				errCh <- fmt.Errorf("read error at %d/%d: %w", totalRead, totalExpected, err)
				return
			}
			allData = append(allData, buf[:n]...)
			totalRead += n
		}

		// Verify each chunk
		errors := 0
		for i := 0; i < numChunks; i++ {
			start := i * chunkSize
			end := start + chunkSize
			if end > len(allData) {
				log.Printf("CHUNK %d: incomplete data (have %d bytes)", i, len(allData)-start)
				break
			}
			chunk := allData[start:end]
			h := sha256.Sum256(chunk)
			got := hex.EncodeToString(h[:8])
			if got != hashes[i] {
				errors++
				if errors <= 5 {
					// Find first diff
					expected := chunks[i]
					firstDiff := -1
					for j := 0; j < len(chunk); j++ {
						if chunk[j] != expected[j] {
							firstDiff = j
							break
						}
					}
					log.Printf("CHUNK %d MISMATCH: first_diff_at=%d chunkSize=%d",
						i, firstDiff, chunkSize)
					if firstDiff >= 0 {
						ctx := 16
						startCtx := firstDiff - ctx
						if startCtx < 0 {
							startCtx = 0
						}
						endCtx := firstDiff + ctx
						if endCtx > len(chunk) {
							endCtx = len(chunk)
						}
						log.Printf("  EXPECTED[%d:%d]=%x", startCtx, endCtx, expected[startCtx:endCtx])
						log.Printf("  GOT     [%d:%d]=%x", startCtx, endCtx, chunk[startCtx:endCtx])
					}
				}
			}
		}
		if errors > 0 {
			errCh <- fmt.Errorf("%d/%d chunks MISMATCH", errors, numChunks)
			return
		}
		log.Printf("All %d chunks verified OK", numChunks)
	}()

	// Sender
	time.Sleep(100 * time.Millisecond) // wait for listener
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.DialTimeout("tcp", "127.0.0.1:19998", 5*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		for i, chunk := range chunks {
			preHash := sha256.Sum256(chunk)
			_, err := conn.Write(chunk)
			if err != nil {
				errCh <- fmt.Errorf("write chunk %d: %w", i, err)
				return
			}
			postHash := sha256.Sum256(chunk)
			if postHash != preHash {
				errCh <- fmt.Errorf("chunk %d corrupted during write: pre=%s post=%s",
					i, hex.EncodeToString(preHash[:8]), hex.EncodeToString(postHash[:8]))
				return
			}
		}
		log.Printf("All %d chunks sent", numChunks)
	}()

	wg.Wait()
	select {
	case err := <-errCh:
		log.Printf("FAIL: %v", err)
		os.Exit(1)
	default:
		log.Println("PASS")
	}
}
