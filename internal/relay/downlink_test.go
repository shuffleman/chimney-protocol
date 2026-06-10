package relay

import (
	"io"
	"testing"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/profile"
	"github.com/shuffleman/chimney-protocol/internal/record"
)

// newTestEngine 构造一个把记录写入 pipe 的 Engine,便于读回断言。
func newTestEngine(t *testing.T) (*h2engine.Engine, *record.RecordReader, *io.PipeWriter) {
	t.Helper()
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	codec, err := record.NewCodec(key, nonce)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	engine := h2engine.NewEngine(h2engine.DefaultSettings(), codec)
	pr, pw := io.Pipe()
	engine.SetRecordIO(nil, record.NewRecordWriter(pw, codec))
	return engine, record.NewRecordReader(pr, codec), pw
}

func TestNewDownlinkShaper_Disabled(t *testing.T) {
	// nil 配置与未开启 StealthMode 都应得到禁用的空操作塑形器。
	if s := newDownlinkShaper(nil, nil); s.enabled {
		t.Error("nil config should yield disabled shaper")
	}
	if s := newDownlinkShaper(&Config{StealthMode: false}, nil); s.enabled {
		t.Error("StealthMode=false should yield disabled shaper")
	}
}

func TestNewDownlinkShaper_Defaults(t *testing.T) {
	s := newDownlinkShaper(&Config{StealthMode: true}, nil)
	if !s.enabled {
		t.Fatal("StealthMode=true should enable shaper")
	}
	// 空等级应回退到 medium 预设。
	wantMedium := dilutionLevels["medium"]
	if s.ratioTarget != wantMedium.ratio {
		t.Errorf("ratioTarget = %v, want medium %v", s.ratioTarget, wantMedium.ratio)
	}

	// 负值应被原样保留以关闭注水。
	s2 := newDownlinkShaper(&Config{StealthMode: true, DownlinkRatioTarget: -1}, nil)
	if s2.ratioTarget != -1 {
		t.Errorf("negative ratioTarget should be preserved, got %v", s2.ratioTarget)
	}
}

func TestNewDownlinkShaper_Levels(t *testing.T) {
	// 各等级的目标比应单调递增,区间应有效。
	var prevRatio float64
	for _, name := range []string{"low", "medium", "high", "max"} {
		s := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: name}, nil)
		if !s.enabled {
			t.Fatalf("%s: shaper should be enabled", name)
		}
		if s.ratioTarget <= prevRatio {
			t.Errorf("%s: ratioTarget %v should exceed previous %v", name, s.ratioTarget, prevRatio)
		}
		if s.minInterval <= 0 || s.maxInterval <= s.minInterval {
			t.Errorf("%s: invalid interval [%v,%v]", name, s.minInterval, s.maxInterval)
		}
		prevRatio = s.ratioTarget
	}

	// off 等级:不注水(needsFill 始终 false),但记录 padding 仍生效。
	off := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: "off"}, nil)
	if !off.enabled {
		t.Fatal("off: shaper should still be enabled for record padding")
	}
	off.recordUp(10000)
	if off.needsFill() {
		t.Error("off level should never request fill")
	}
	if off.targetSize() != minDownlinkRecord {
		t.Errorf("off: targetSize = %d, want %d", off.targetSize(), minDownlinkRecord)
	}

	// 未知等级回退到 medium。
	unknown := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: "bogus"}, nil)
	if unknown.ratioTarget != dilutionLevels["medium"].ratio {
		t.Errorf("unknown level: ratioTarget = %v, want medium", unknown.ratioTarget)
	}

	// 显式 DownlinkRatioTarget 覆盖等级预设比值。
	override := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: "low", DownlinkRatioTarget: 9}, nil)
	if override.ratioTarget != 9 {
		t.Errorf("explicit override: ratioTarget = %v, want 9", override.ratioTarget)
	}
}

func TestDownlinkShaper_TargetSizeClamp(t *testing.T) {
	// 固定大小低于下限 → 补到下限。
	s := newDownlinkShaper(&Config{StealthMode: true, DownlinkRecordSize: 10}, nil)
	if got := s.targetSize(); got != minDownlinkRecord {
		t.Errorf("targetSize below min: got %d, want %d", got, minDownlinkRecord)
	}

	// 固定大小高于上限 → 夹到上限。
	s = newDownlinkShaper(&Config{StealthMode: true, DownlinkRecordSize: 100000}, nil)
	if got := s.targetSize(); got != maxDownlinkRecord {
		t.Errorf("targetSize above max: got %d, want %d", got, maxDownlinkRecord)
	}

	// 无固定大小、无 profile → 回退到下限。
	s = newDownlinkShaper(&Config{StealthMode: true}, nil)
	if got := s.targetSize(); got != minDownlinkRecord {
		t.Errorf("targetSize no-profile fallback: got %d, want %d", got, minDownlinkRecord)
	}

	// 有 profile → 采样值始终落在 [min, max] 区间。
	s = newDownlinkShaper(&Config{StealthMode: true}, profile.DefaultModel())
	for i := 0; i < 200; i++ {
		got := s.targetSize()
		if got < minDownlinkRecord || got > maxDownlinkRecord {
			t.Fatalf("profile-sampled targetSize out of range: %d", got)
		}
	}
}

func TestDownlinkShaper_RatioAccounting(t *testing.T) {
	s := newDownlinkShaper(&Config{StealthMode: true, DownlinkRatioTarget: 5}, nil)

	// 没有任何上行 → 不需要注水(避免空闲连接被强行灌流量)。
	if s.needsFill() {
		t.Error("needsFill should be false with zero upstream")
	}

	// 上行 1000,目标比 5 → 需要 5000 下行。当前 down=0 → 需要注水。
	s.recordUp(1000)
	if !s.needsFill() {
		t.Error("needsFill should be true when down:up below target")
	}

	// 补足下行后不再需要。
	s.recordDown(5000)
	if s.needsFill() {
		t.Error("needsFill should be false once ratio target met")
	}
}

func TestDownlinkShaper_DisabledAccountingNoop(t *testing.T) {
	s := newDownlinkShaper(&Config{StealthMode: false}, nil)
	s.recordUp(1000)
	s.recordDown(1000)
	if s.needsFill() {
		t.Error("disabled shaper must never request fill")
	}
}

func TestDownlinkShaper_WriteResponsePads(t *testing.T) {
	engine, reader, pw := newTestEngine(t)
	s := newDownlinkShaper(&Config{StealthMode: true, DownlinkRecordSize: 896, DownlinkRatioTarget: -1}, nil)

	payload := []byte{0x02, 'h', 'i'} // 小响应,远小于 896
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		if err := s.writeResponse(engine, 1, payload); err != nil {
			t.Errorf("writeResponse: %v", err)
		}
		pw.Close()
	}()

	plaintext, err := reader.ReadRecord()
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	<-writeDone // 确保 recordDown 已执行,再断言下行字节

	// 记录应被补齐到约 896 字节(隧道帧 + padding 帧合并在一条记录里)。
	if len(plaintext) < 896-h2engine.FrameHeaderLen {
		t.Errorf("padded record too small: %d bytes, want ~896", len(plaintext))
	}

	// 第一帧:流 1 的隧道 DATA。
	fh1, err := h2engine.DecodeFrameHeader(plaintext)
	if err != nil {
		t.Fatalf("DecodeFrameHeader: %v", err)
	}
	if fh1.StreamID != 1 || fh1.Type != h2engine.FrameData {
		t.Errorf("first frame: stream=%d type=0x%x, want stream 1 DATA", fh1.StreamID, fh1.Type)
	}

	// 第二帧:padding 流(客户端会丢弃)。
	rest := plaintext[h2engine.FrameHeaderLen+int(fh1.Length):]
	fh2, err := h2engine.DecodeFrameHeader(rest)
	if err != nil {
		t.Fatalf("DecodeFrameHeader (padding): %v", err)
	}
	if !h2engine.IsPaddingStream(fh2.StreamID) {
		t.Errorf("second frame stream=%d, want padding stream", fh2.StreamID)
	}

	// 下行字节应已记账到目标大小附近。
	if s.downBytes.Load() < 896 {
		t.Errorf("downBytes = %d, want >= 896", s.downBytes.Load())
	}
}

func TestDownlinkShaper_InjectTowardConverges(t *testing.T) {
	engine, _ := newCountingEngine(t)
	s := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: "medium", DownlinkRecordSize: 896}, nil)

	// 上行 10000B,目标比 5 → 下行应被补到 ~50000B。
	s.recordUp(10000)
	if !s.needsFill() {
		t.Fatal("should need fill before any downstream")
	}

	// 给足记录配额、无突发内睡眠 → 一次性收敛到目标。
	s.injectToward(engine, 1000, 0)

	down := s.downBytes.Load()
	if down < 50000 {
		t.Errorf("after injectToward downBytes=%d, want >=50000 (5x up)", down)
	}
	if s.needsFill() {
		t.Errorf("should not need fill after reaching target; down=%d up=%d", down, s.upBytes.Load())
	}
}

func TestDownlinkShaper_BurstRespectsMaxBurst(t *testing.T) {
	engine, _ := newCountingEngine(t)
	s := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: "max", DownlinkRecordSize: 896}, nil)

	// 制造远超 maxBurst 的缺口:up=1MB,目标 12 → 缺口 ~12MB。
	s.recordUp(1 << 20)

	// burstRecords 应被 maxBurst 上限约束。
	want := s.maxBurst / 896
	if got := s.burstRecords(); got != want {
		t.Errorf("burstRecords = %d, want %d (maxBurst cap)", got, want)
	}

	// 单个突发注入应被限制在 ~maxBurst 内。
	injected := s.injectToward(engine, s.burstRecords(), 0)
	if injected > s.maxBurst+896 {
		t.Errorf("single burst injected %d bytes, exceeds maxBurst %d", injected, s.maxBurst)
	}
	// 巨大缺口 → 一个突发后仍需继续注水。
	if !s.needsFill() {
		t.Error("huge deficit should still need fill after one capped burst")
	}
}

func TestDownlinkShaper_GovernorInjectsFill(t *testing.T) {
	engine, reader, pw := newTestEngine(t)
	s := newDownlinkShaper(&Config{StealthMode: true, DownlinkRecordSize: 896, DownlinkRatioTarget: 5}, nil)

	// 制造不平衡:大量上行、零下行 → governor 应注水。
	s.recordUp(10000)

	done := make(chan struct{})
	go s.runInjector(engine, done)

	// 读到一条注入的记录(io.Pipe 同步,会阻塞到 governor 写出)。
	recordCh := make(chan []byte, 1)
	go func() {
		pt, err := reader.ReadRecord()
		if err == nil {
			recordCh <- pt
		} else {
			close(recordCh)
		}
	}()

	select {
	case pt, ok := <-recordCh:
		if !ok {
			t.Fatal("reader closed before governor injected a record")
		}
		fh, err := h2engine.DecodeFrameHeader(pt)
		if err != nil {
			t.Fatalf("DecodeFrameHeader: %v", err)
		}
		if !h2engine.IsPaddingStream(fh.StreamID) {
			t.Errorf("injected frame stream=%d, want padding stream", fh.StreamID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("governor did not inject fill within 2s")
	}

	close(done)
	pw.Close()
}
