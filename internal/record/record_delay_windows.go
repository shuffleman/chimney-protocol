//go:build windows

package record

import "time"

// maxWriteChunk 是 Windows 回环上每次 Write 调用的最大字节数。
// Windows TCP 回环驱动会在多个 goroutine 驱动单个连接时，损坏
// 大于 8192 字节（2 个内存页）的写入的后半部分（第 2 页及以后）。
// 在 8192 字节处分割可防止此问题。
// 参见 cmd/tcp_page_test 和 cmd/upload_debug 获取复现证据。
const maxWriteChunk = 8192

// writeDelay 给内核时间提交上一次写入，
// 然后再开始下一次写入，防止 Windows 回环写入重排序竞争。
func writeDelay() {
	time.Sleep(10 * time.Microsecond)
}
