package chimney

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/record"
)

// liveTestTunnel 构造一条可成功开流的隧道(记录写入 io.Discard),无需真实
// 网络/中继。后台应答 goroutine 向每条新流注入一次 CONNECT_OK,使
// dialContext 能返回 streamConn。
func liveTestTunnel(t *testing.T, chanBuf int) *tunnel {
	t.Helper()
	codec, err := record.NewCodec(make([]byte, 16), make([]byte, 12))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	eng := h2engine.NewEngine(h2engine.DefaultSettings(), codec)
	eng.SetRecordIO(nil, record.NewRecordWriter(io.Discard, codec))
	tun := &tunnel{
		h2Eng:   eng,
		chanBuf: chanBuf,
		dead:    make(chan struct{}),
		quit:    make(chan struct{}),
		streams: make(map[uint32]chan *streamFrame),
	}

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		acked := map[uint32]bool{}
		ok := &streamFrame{fh: &h2engine.FrameHeader{Type: h2engine.FrameData}, payload: []byte{0x01}}
		for {
			select {
			case <-stop:
				return
			default:
			}
			tun.mu.Lock()
			for id, ch := range tun.streams {
				if !acked[id] {
					select {
					case ch <- ok:
						acked[id] = true
					default:
					}
				}
			}
			tun.mu.Unlock()
			time.Sleep(time.Millisecond)
		}
	}()
	return tun
}

func TestWriteBufSizeBounded(t *testing.T) {
	if writeBufSize != 1+maxTunnelDataChunk {
		t.Errorf("writeBufSize = %d, want %d", writeBufSize, 1+maxTunnelDataChunk)
	}
	if writeBufSize > 17*1024 {
		t.Errorf("writeBufSize %d too large (regression to 64KB pool?)", writeBufSize)
	}
}

func TestNormalizeStreamMemoryDefaults(t *testing.T) {
	c := Config{RelayAddr: "r:443", SNI: "s", UserID: "u"}
	if err := c.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if c.StreamChannelBuffer != DefaultStreamChannelBuffer {
		t.Errorf("StreamChannelBuffer = %d, want %d", c.StreamChannelBuffer, DefaultStreamChannelBuffer)
	}
	// 负值的并发上限应被规整为 0(不限)。
	c2 := Config{RelayAddr: "r:443", SNI: "s", UserID: "u", MaxConcurrentStreams: -5}
	if err := c2.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if c2.MaxConcurrentStreams != 0 {
		t.Errorf("negative MaxConcurrentStreams = %d, want 0", c2.MaxConcurrentStreams)
	}
}

func TestStreamChannelBufferApplied(t *testing.T) {
	const want = 16
	d := &Dialer{
		config: Config{StreamChannelBuffer: want},
		pool:   []*tunnel{liveTestTunnel(t, want)},
	}
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	sc, ok := conn.(*streamConn)
	if !ok {
		t.Fatalf("conn type %T, want *streamConn", conn)
	}
	if cap(sc.ch) != want {
		t.Errorf("stream channel cap = %d, want %d", cap(sc.ch), want)
	}
}

func TestMaxConcurrentStreamsCaps(t *testing.T) {
	d := &Dialer{
		config:    Config{StreamChannelBuffer: 8, MaxConcurrentStreams: 2},
		pool:      []*tunnel{liveTestTunnel(t, 8)},
		streamSem: make(chan struct{}, 2),
	}

	// 前两条流应立即成功。
	c1, err := d.DialContext(context.Background(), "tcp", "a:1")
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	if _, err := d.DialContext(context.Background(), "tcp", "b:2"); err != nil {
		t.Fatalf("dial 2: %v", err)
	}

	// 第三条应被配额阻塞:用短超时 ctx → 返回 ctx 错误。
	ctx3, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := d.DialContext(ctx3, "tcp", "c:3"); err == nil {
		t.Fatal("dial 3 should block until a slot frees, but succeeded")
	}

	// 关闭一条 → 释放配额 → 第三条成功。
	if err := c1.Close(); err != nil {
		t.Logf("close c1: %v (non-fatal)", err)
	}
	ctx4, cancel4 := context.WithTimeout(context.Background(), time.Second)
	defer cancel4()
	if _, err := d.DialContext(ctx4, "tcp", "c:3"); err != nil {
		t.Fatalf("dial after freeing a slot should succeed: %v", err)
	}
}

func TestListenPacketCountsAgainstMaxConcurrentStreams(t *testing.T) {
	d := &Dialer{
		config:    Config{StreamChannelBuffer: 8, MaxConcurrentStreams: 1},
		pool:      []*tunnel{liveTestTunnel(t, 8)},
		streamSem: make(chan struct{}, 1),
	}

	pc1, err := d.ListenPacket(context.Background())
	if err != nil {
		t.Fatalf("first ListenPacket failed: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel2()
	if _, err := d.ListenPacket(ctx2); err == nil {
		t.Fatal("second ListenPacket should block on stream limit, but succeeded")
	}

	if err := pc1.Close(); err != nil {
		t.Fatalf("close first PacketConn: %v", err)
	}

	ctx3, cancel3 := context.WithTimeout(context.Background(), time.Second)
	defer cancel3()
	pc2, err := d.ListenPacket(ctx3)
	if err != nil {
		t.Fatalf("ListenPacket after freeing a slot should succeed: %v", err)
	}
	_ = pc2.Close()
}

func TestClosedStreamsReleaseH2EngineState(t *testing.T) {
	tun := liveTestTunnel(t, 8)
	d := &Dialer{
		config: Config{StreamChannelBuffer: 8},
		pool:   []*tunnel{tun},
	}

	for i := 0; i < 1000; i++ {
		conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
		if err != nil {
			t.Fatalf("DialContext #%d: %v", i, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i, err)
		}
	}

	if got := tun.h2Eng.StreamCount(); got != 0 {
		t.Fatalf("h2 stream states after closing short streams = %d, want 0", got)
	}
}

func TestUDPConnWriteDeadlinePropagatesToStream(t *testing.T) {
	u := &udpConn{
		stream: &streamConn{
			t:  &tunnel{quit: make(chan struct{})},
			ch: make(chan *streamFrame),
		},
	}
	if err := u.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}

	_, err := u.WriteTo([]byte("query"), &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected net timeout error, got %T %v", err, err)
	}
}
