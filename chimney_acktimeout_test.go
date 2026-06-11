package chimney

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/record"
)

// TestDialContextConnectAckTimeout 验证:CONNECT_OK 超时时只失败当前流,
// 不拆掉整条隧道,避免慢目标站/DNS 连带影响同隧道上的其它流。
func TestDialContextConnectAckTimeout(t *testing.T) {
	codec, err := record.NewCodec(make([]byte, 16), make([]byte, 12))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	eng := h2engine.NewEngine(h2engine.DefaultSettings(), codec)
	eng.SetRecordIO(nil, record.NewRecordWriter(io.Discard, codec))

	// 假死隧道:无应答 goroutine → 永不回 CONNECT_OK。
	c1, c2 := net.Pipe()
	defer c2.Close()
	tun := &tunnel{
		h2Eng:   eng,
		rawConn: c1, // 让异步 closeTunnel 的 rawConn.Close() 可用
		chanBuf: 8,
		dead:    make(chan struct{}),
		quit:    make(chan struct{}),
		streams: make(map[uint32]chan *streamFrame),
	}
	// 模拟 dispatchFrames:quit 关闭时关闭 dead,让 closeTunnel 不悬挂。
	go func() { <-tun.quit; close(tun.dead) }()

	start := time.Now()
	conn, derr := tun.dialContext(context.Background(), "example.com:443")
	elapsed := time.Since(start)

	if conn != nil {
		t.Fatal("expected nil conn on ack timeout")
	}
	if derr == nil || !strings.Contains(derr.Error(), "CONNECT ack timeout") {
		t.Errorf("err = %v, want CONNECT ack timeout", derr)
	}
	if isTunnelUnavailable(derr) {
		t.Errorf("err %v should not be classified tunnel-unavailable", derr)
	}
	select {
	case <-tun.quit:
		t.Fatal("CONNECT ack timeout closed the whole tunnel")
	default:
	}
	if elapsed < connectAckTimeout || elapsed > connectAckTimeout+2*time.Second {
		t.Errorf("dialContext returned in %v, want ~%v", elapsed, connectAckTimeout)
	}
}
