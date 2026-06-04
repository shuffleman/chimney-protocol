//go:build !windows

package record

// maxWriteChunk：非 Windows 平台不需要分块。
const maxWriteChunk = 0

func writeDelay() {}
