//go:build windows

package record

import "time"

// writeDelay prevents a Windows TCP loopback driver race condition
// where back-to-back writes of multi-page buffers cause data loss or
// corruption. 10us gives the kernel time to complete the previous write.
// See cmd/tcp_page_test for reproduction and verification.
func writeDelay() {
	time.Sleep(10 * time.Microsecond)
}
