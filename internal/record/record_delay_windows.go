//go:build windows

package record

import "time"

// maxWriteChunk is the maximum bytes per Write call on Windows loopback.
// The Windows TCP loopback driver corrupts the second half (pages 2+) of
// writes larger than 8192 bytes (2 memory pages) when multiple goroutines
// drive a single socket under load. Splitting at 8192 bytes prevents this.
// See cmd/tcp_page_test and cmd/upload_debug for reproduction evidence.
const maxWriteChunk = 8192

// writeDelay gives the kernel time to commit the previous write before
// the next one begins, preventing Windows loopback write-reorder races.
func writeDelay() {
	time.Sleep(10 * time.Microsecond)
}
