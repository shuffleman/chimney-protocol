package relay

import (
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/profile"
	"github.com/shuffleman/chimney-protocol/internal/record"
)

// countWriter 统计写入的字节数 = 加密后真实在线下行字节。
type countWriter struct{ n atomic.Int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n.Add(int64(len(p)))
	return len(p), nil
}

func newCountingEngine(t *testing.T) (*h2engine.Engine, *countWriter) {
	t.Helper()
	codec, err := record.NewCodec(make([]byte, 16), make([]byte, 12))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	engine := h2engine.NewEngine(h2engine.DefaultSettings(), codec)
	cw := &countWriter{}
	engine.SetRecordIO(nil, record.NewRecordWriter(cw, codec))
	return engine, cw
}

// TestMeasure_RecordPadding 测量下行逐记录 padding 的字节放大(确定性,与等级无关)。
// 运行: go test ./internal/relay/ -run TestMeasure_RecordPadding -v
func TestMeasure_RecordPadding(t *testing.T) {
	const recordTarget = 896 // 固定下行记录目标,消除 profile 随机性
	fmt.Printf("\n=== 记录 padding 放大 (target=%dB 明文, 与注水等级无关) ===\n", recordTarget)
	fmt.Printf("%-12s %-14s %-14s %-10s\n", "app载荷", "在线下行字节", "放大", "说明")
	for _, p := range []int{64, 256, 512, 896, 1400, 4096, 16000} {
		engine, cw := newCountingEngine(t)
		s := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: "off", DownlinkRecordSize: recordTarget}, nil)
		payload := make([]byte, p)
		payload[0] = 0x02
		if err := s.writeResponse(engine, 1, payload); err != nil {
			t.Fatalf("writeResponse(%d): %v", p, err)
		}
		wire := cw.n.Load()
		note := "补齐到目标"
		if p >= recordTarget {
			note = "≥目标,不补"
		}
		fmt.Printf("%-12d %-14d %-13.2fx %-10s\n", p, wire, float64(wire)/float64(p), note)
	}
}

// TestMeasure_GovernorRate 测量注水 governor 在各等级下的最大注入速率。
// 强制 needsFill 恒为真(海量 up、零 down),运行固定窗口,统计注入的在线字节。
// 运行: go test ./internal/relay/ -run TestMeasure_GovernorRate -v -timeout 60s
func TestMeasure_GovernorRate(t *testing.T) {
	if testing.Short() {
		t.Skip("定时测量,-short 跳过")
	}
	const window = 2 * time.Second
	const recordTarget = 896
	fmt.Printf("\n=== governor 最大注入速率 (record=%dB, 窗口=%v) ===\n", recordTarget, window)
	fmt.Printf("%-10s %-16s %-16s\n", "等级", "注入在线字节", "注入速率")
	for _, level := range []string{"off", "low", "medium", "high", "max"} {
		engine, cw := newCountingEngine(t)
		s := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: level, DownlinkRecordSize: recordTarget}, nil)
		s.recordUp(1 << 40) // 制造永久不平衡 → needsFill 恒真
		done := make(chan struct{})
		go s.runInjector(engine, done)
		time.Sleep(window)
		close(done)
		time.Sleep(100 * time.Millisecond) // 等在途注入落定
		bytes := cw.n.Load()
		rate := float64(bytes) / window.Seconds() / 1024.0
		fmt.Printf("%-10s %-16d %-13.1f KB/s\n", level, bytes, rate)
	}
}

// TestMeasure_SymmetricStream 在对称流量(up=down,逐条小消息)下,实测各等级
// 的总下行在线放大与 governor 实际达成的 down:up 比。
// 运行: go test ./internal/relay/ -run TestMeasure_SymmetricStream -v -timeout 120s
func TestMeasure_SymmetricStream(t *testing.T) {
	if testing.Short() {
		t.Skip("定时测量,-short 跳过")
	}
	const (
		window       = 3 * time.Second
		msgSize      = 1024 // app 层每条消息字节(up 与 down 各一条)
		sendEvery    = 5 * time.Millisecond
		recordTarget = 896 // < msgSize → 真实 down 记录不被 padding,隔离出注水效果
	)
	fmt.Printf("\n=== 对称流量实测 (msg=%dB, 每%v一轮, 窗口=%v, record=%dB) ===\n",
		msgSize, sendEvery, window, recordTarget)
	fmt.Printf("理想下:每方约 %.0f KB/s\n", float64(msgSize)/sendEvery.Seconds()/1024)
	fmt.Printf("%-10s %-14s %-14s %-16s %-12s\n", "等级", "真实down载荷", "在线down字节", "下行放大", "达成down:up")

	for _, level := range []string{"off", "medium", "max"} {
		engine, cw := newCountingEngine(t)
		s := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: level, DownlinkRecordSize: recordTarget}, nil)
		done := make(chan struct{})
		go s.runInjector(engine, done)

		var realDownPayload int64
		stop := time.After(window)
		ticker := time.NewTicker(sendEvery)
	loop:
		for {
			select {
			case <-stop:
				break loop
			case <-ticker.C:
				s.recordUp(msgSize) // 模拟上行 app 消息
				resp := make([]byte, 1+msgSize)
				resp[0] = 0x02
				if err := s.writeResponse(engine, 1, resp); err != nil {
					t.Fatalf("%s writeResponse: %v", level, err)
				}
				realDownPayload += int64(msgSize)
			}
		}
		ticker.Stop()
		close(done)
		time.Sleep(120 * time.Millisecond)

		wireDown := cw.n.Load()
		up := s.upBytes.Load()
		down := s.downBytes.Load()
		ratio := 0.0
		if up > 0 {
			ratio = float64(down) / float64(up)
		}
		fmt.Printf("%-10s %-14d %-14d %-15.2fx %-12.2f\n",
			level, realDownPayload, wireDown, float64(wireDown)/float64(realDownPayload), ratio)
	}
}

// TestMeasure_SymmetricProfileRecords 用生产配置(profile 采样记录,~3KB,像真实
// 下载)在对称流量下复测:更大的注入记录在相同的真实节奏(intra)下吞吐上限高得多,
// 因此能在保持时序真实的同时达成目标比。msg 取较大值以避免真实下行被记录 padding 拉高。
// 运行: go test ./internal/relay/ -run TestMeasure_SymmetricProfileRecords -v -timeout 90s
func TestMeasure_SymmetricProfileRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("定时测量,-short 跳过")
	}
	const (
		window    = 3 * time.Second
		msgSize   = 8192 // 大于多数 profile 采样记录,真实下行基本不被 padding
		sendEvery = 40 * time.Millisecond
	)
	prof := profile.DefaultModel()
	fmt.Printf("\n=== 对称流量·生产配置(profile采样记录, record_size=0) ===\n")
	fmt.Printf("理想下:每方约 %.0f KB/s\n", float64(msgSize)/sendEvery.Seconds()/1024)
	fmt.Printf("%-10s %-14s %-16s %-12s\n", "等级", "在线down字节", "下行放大", "达成down:up")

	for _, level := range []string{"off", "medium", "max"} {
		engine, cw := newCountingEngine(t)
		// DownlinkRecordSize 留 0 → 走 profile 采样;传入 prof 让注入与 pacing 都用真实分布。
		s := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: level}, prof)
		done := make(chan struct{})
		go s.runInjector(engine, done)

		var realDown int64
		stop := time.After(window)
		ticker := time.NewTicker(sendEvery)
	loop:
		for {
			select {
			case <-stop:
				break loop
			case <-ticker.C:
				s.recordUp(msgSize)
				resp := make([]byte, 1+msgSize)
				resp[0] = 0x02
				if err := s.writeResponse(engine, 1, resp); err != nil {
					t.Fatalf("%s writeResponse: %v", level, err)
				}
				realDown += int64(msgSize)
			}
		}
		ticker.Stop()
		close(done)
		time.Sleep(120 * time.Millisecond)

		up := s.upBytes.Load()
		down := s.downBytes.Load()
		ratio := 0.0
		if up > 0 {
			ratio = float64(down) / float64(up)
		}
		fmt.Printf("%-10s %-14d %-15.2fx %-12.2f\n",
			level, cw.n.Load(), float64(cw.n.Load())/float64(realDown), ratio)
	}
}

// tsWriter 记录每条记录(每次底层 Write)的发出时刻,用于计算 inter_arrival。
type tsWriter struct {
	mu sync.Mutex
	ts []time.Time
}

func (w *tsWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.ts = append(w.ts, time.Now())
	w.mu.Unlock()
	return len(p), nil
}

func newTSEngine(t *testing.T) (*h2engine.Engine, *tsWriter) {
	t.Helper()
	codec, err := record.NewCodec(make([]byte, 16), make([]byte, 12))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	engine := h2engine.NewEngine(h2engine.DefaultSettings(), codec)
	w := &tsWriter{}
	engine.SetRecordIO(nil, record.NewRecordWriter(w, codec))
	return engine, w
}

// interArrivalStats 返回记录发出间隔的 均值/标准差/最大值(毫秒)与样本数。
func interArrivalStats(ts []time.Time) (meanMs, stdMs, maxMs float64, n int) {
	if len(ts) < 2 {
		return 0, 0, 0, len(ts)
	}
	gaps := make([]float64, 0, len(ts)-1)
	var sum, max float64
	for i := 1; i < len(ts); i++ {
		g := float64(ts[i].Sub(ts[i-1]).Microseconds()) / 1000.0 // ms
		gaps = append(gaps, g)
		sum += g
		if g > max {
			max = g
		}
	}
	mean := sum / float64(len(gaps))
	var sq float64
	for _, g := range gaps {
		d := g - mean
		sq += d * d
	}
	return mean, math.Sqrt(sq / float64(len(gaps))), max, len(gaps) + 1
}

// TestMeasure_InjectionTiming 对比注入记录的 inter_arrival 时序特征:
//   - paced  : 新的按 profile 节奏分突发注入(runInjector)
//   - unpaced: 旧的零间隔猛灌(injectToward intra=0)
//   - 参考    : profile 的突发内节奏分布(真实下载的 think-time 形态)
//
// 运行: go test ./internal/relay/ -run TestMeasure_InjectionTiming -v -timeout 60s
func TestMeasure_InjectionTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("定时测量,-short 跳过")
	}
	prof := profile.DefaultModel()
	fmt.Printf("\n=== 注入 inter_arrival 时序对比 (ms) ===\n")
	fmt.Printf("%-10s %-10s %-10s %-10s %-8s\n", "方式", "均值", "标准差", "最大", "样本")

	// paced:运行 2s,持续落后 → 持续按节奏注入。
	{
		engine, w := newTSEngine(t)
		s := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: "medium", DownlinkRecordSize: 896}, prof)
		s.recordUp(1 << 40) // 永久缺口
		done := make(chan struct{})
		go s.runInjector(engine, done)
		time.Sleep(2 * time.Second)
		close(done)
		time.Sleep(50 * time.Millisecond)
		w.mu.Lock()
		mean, std, max, n := interArrivalStats(w.ts)
		w.mu.Unlock()
		fmt.Printf("%-10s %-10.3f %-10.3f %-10.3f %-8d\n", "paced", mean, std, max, n)
	}

	// unpaced:一次性猛灌 3000 条记录(模拟旧的零间隔注入)。
	{
		engine, w := newTSEngine(t)
		s := newDownlinkShaper(&Config{StealthMode: true, DownlinkLevel: "medium", DownlinkRecordSize: 896}, prof)
		s.recordUp(1 << 40)
		s.injectToward(engine, 3000, 0)
		w.mu.Lock()
		mean, std, max, n := interArrivalStats(w.ts)
		w.mu.Unlock()
		fmt.Printf("%-10s %-10.3f %-10.3f %-10.3f %-8d\n", "unpaced", mean, std, max, n)
	}

	// 参考:profile 突发内节奏 + 突发间 gap 的合成分布。
	{
		var ts []time.Time
		now := time.Now()
		for b := 0; b < 60; b++ {
			bl := int(prof.BurstLength())
			for i := 0; i < bl; i++ {
				now = now.Add(prof.RecordDelay())
				ts = append(ts, now)
			}
			now = now.Add(prof.BurstGap())
		}
		mean, std, max, n := interArrivalStats(ts)
		fmt.Printf("%-10s %-10.3f %-10.3f %-10.3f %-8d\n", "参考profile", mean, std, max, n)
	}
}

// 确保 io.Writer 接口满足。
var (
	_ io.Writer = (*countWriter)(nil)
	_ io.Writer = (*tsWriter)(nil)
)
