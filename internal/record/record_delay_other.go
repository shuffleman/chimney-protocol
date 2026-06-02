//go:build !windows

package record

// maxWriteChunk: no chunking needed on non-Windows platforms.
const maxWriteChunk = 0

func writeDelay() {}
