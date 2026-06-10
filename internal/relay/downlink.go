package relay

import (
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/profile"
)

// 下行流量塑形常量。
const (
	// minDownlinkRecord 是下行记录 padding 的最小目标大小。
	// 小于此值的记录会被补齐，避免暴露隧道的小封装块。
	minDownlinkRecord = 512

	// maxDownlinkRecord 是单条 TLS 记录的明文上限（2^14）。
	// 超过会被 TLS 层拆成多条记录，破坏我们想要的尺寸分布。
	maxDownlinkRecord = 16384

	// governorMinInterval / governorMaxInterval 是注水节奏的兜底区间,
	// 当等级未给出有效区间时使用。避免恒定速率注入形成时序指纹。
	governorMinInterval = 40 * time.Millisecond
	governorMaxInterval = 250 * time.Millisecond

	// defaultDilutionLevel 是 StealthMode 开启但未指定等级时的默认注水等级。
	defaultDilutionLevel = "medium"

	// defaultDilutionBurst 是单次下行写入触发的比例注入字节上限。
	// 它平滑突发:缺口超过上限时分摊到后续多次写入逐步补齐,
	// 避免单次灌入巨量填充。足够大以在常见吞吐下跟上目标比。
	defaultDilutionBurst = 64 * 1024
)

// dilutionPreset 是一个注水等级对应的参数:目标 down:up 比与注入节奏区间。
// 等级越高,下行注水越激进(更高的目标比 + 更密的注入),伪装越强但下行
// 带宽开销越大。
type dilutionPreset struct {
	ratio       float64
	minInterval time.Duration
	maxInterval time.Duration
}

// dilutionLevels 把等级名映射到参数。off 仅做逐记录 padding、不注水。
//
//	off    — 不注水(仅记录 padding)
//	low    — 轻度,down:up≈2.5  (up_down_ratio≈0.4)
//	medium — 默认,down:up≈5    (up_down_ratio≈0.2,贴近真实浏览)
//	high   — 激进,down:up≈8    (up_down_ratio≈0.125)
//	max    — 最强,down:up≈12   (最强伪装,下行带宽开销最大)
var dilutionLevels = map[string]dilutionPreset{
	"off":    {ratio: 0},
	"low":    {ratio: 2.5, minInterval: 80 * time.Millisecond, maxInterval: 400 * time.Millisecond},
	"medium": {ratio: 5.0, minInterval: 40 * time.Millisecond, maxInterval: 250 * time.Millisecond},
	"high":   {ratio: 8.0, minInterval: 25 * time.Millisecond, maxInterval: 150 * time.Millisecond},
	"max":    {ratio: 12.0, minInterval: 15 * time.Millisecond, maxInterval: 80 * time.Millisecond},
}

// resolveDilutionLevel 返回给定等级名的预设,未知名回退到默认等级。
func resolveDilutionLevel(name string) dilutionPreset {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		key = defaultDilutionLevel
	}
	if preset, ok := dilutionLevels[key]; ok {
		return preset
	}
	return dilutionLevels[defaultDilutionLevel]
}

// downlinkShaper 对 relay→client(下行)方向做流量塑形,使代理流量在
// 记录大小、上下行字节比和满 MTU 占比上贴近真实 HTTPS 下载行为。
//
// 它解决两类被检测特征:
//   - appdata_record_median / mtu_pkt_ratio: 把下行记录补齐到按 profile
//     采样的较大尺寸(偏向大记录),产生满 MTU 的 TCP 包。
//   - up_down_ratio / downstream_upstream_pkt_ratio: 通过 governor 在下行
//     方向主动注入填充记录,把 down:up 字节比推到目标值,制造"下载型"形态。
//
// 零值(enabled=false)是安全的空操作,relay 行为与未塑形时一致。
type downlinkShaper struct {
	enabled bool

	// prof 提供记录大小分布;为 nil 时回退到 fixedSize/默认采样。
	prof *profile.Model

	// fixedSize>0 时所有下行记录补齐到该固定大小;否则按 prof 采样。
	fixedSize int

	// ratioTarget 是期望的 down:up 字节比。<=0 时关闭 governor 注水,
	// 仅做逐记录 padding。
	ratioTarget float64

	// minInterval/maxInterval 是后台 governor 注水检查的节奏区间(由等级决定)。
	minInterval time.Duration
	maxInterval time.Duration

	// maxBurst 是单次下行写入触发的比例注入字节上限。
	maxBurst int

	upBytes   atomic.Uint64 // client→relay 已观测的上行隧道字节
	downBytes atomic.Uint64 // relay→client 已发送的下行字节(含 padding)
}

// newDownlinkShaper 根据 relay 配置构造下行塑形器。
// 未开启 StealthMode 时返回一个禁用的空操作塑形器。
//
// 注水强度由 DownlinkLevel(off/low/medium/high/max)决定;显式设置非零的
// DownlinkRatioTarget 会覆盖等级的目标比(负值仍表示关闭注水)。
func newDownlinkShaper(cfg *Config, prof *profile.Model) *downlinkShaper {
	if cfg == nil || !cfg.StealthMode {
		return &downlinkShaper{}
	}
	preset := resolveDilutionLevel(cfg.DownlinkLevel)

	ratio := preset.ratio
	if cfg.DownlinkRatioTarget != 0 {
		ratio = cfg.DownlinkRatioTarget // 显式覆盖等级预设
	}

	minIv, maxIv := preset.minInterval, preset.maxInterval
	if minIv <= 0 || maxIv <= minIv {
		minIv, maxIv = governorMinInterval, governorMaxInterval
	}

	return &downlinkShaper{
		enabled:     true,
		prof:        prof,
		fixedSize:   cfg.DownlinkRecordSize,
		ratioTarget: ratio,
		minInterval: minIv,
		maxInterval: maxIv,
		maxBurst:    defaultDilutionBurst,
	}
}

// recordUp 累计上行隧道载荷字节(已剥离命令前缀)。
func (d *downlinkShaper) recordUp(n int) {
	if d.enabled && n > 0 {
		d.upBytes.Add(uint64(n))
	}
}

// recordDown 累计下行已发送字节。
func (d *downlinkShaper) recordDown(n int) {
	if d.enabled && n > 0 {
		d.downBytes.Add(uint64(n))
	}
}

// targetSize 返回下一条下行记录的目标明文大小。
// fixedSize 优先;否则按 profile 采样并夹到 [minDownlinkRecord, maxDownlinkRecord]。
func (d *downlinkShaper) targetSize() uint16 {
	size := d.fixedSize
	if size <= 0 {
		if d.prof != nil {
			size = int(d.prof.RecordSize())
		} else {
			size = minDownlinkRecord
		}
	}
	if size < minDownlinkRecord {
		size = minDownlinkRecord
	}
	if size > maxDownlinkRecord {
		size = maxDownlinkRecord
	}
	return uint16(size)
}

// writeResponse 把后端响应作为下行 DATA 帧写出,并按 targetSize 补齐记录,
// 同时记账下行字节。未启用塑形时退化为普通 WriteData。
func (d *downlinkShaper) writeResponse(e *h2engine.Engine, streamID uint32, payload []byte) error {
	if !d.enabled {
		return e.WriteData(streamID, payload, false)
	}
	target := d.targetSize()
	if err := e.WritePaddedRecord(streamID, payload, target, false); err != nil {
		return err
	}
	// 记账实际下行明文:max(载荷帧, padding 目标)。
	sent := len(payload) + h2engine.FrameHeaderLen
	if int(target) > sent {
		sent = int(target)
	}
	d.recordDown(sent)
	return nil
}

// needsFill 返回当前是否需要注水:已观测到一定上行,且 down:up 比仍低于目标。
func (d *downlinkShaper) needsFill() bool {
	if !d.enabled || d.ratioTarget <= 0 {
		return false
	}
	up := d.upBytes.Load()
	if up == 0 {
		return false
	}
	down := d.downBytes.Load()
	return float64(down) < d.ratioTarget*float64(up)
}

// injectToward 朝 down:up 目标比注入填充记录,最多 maxRecords 条且不超出缺口。
// intra>0 时在记录之间睡眠(突发内节奏),用于让注入呈真实下载的突发形态;
// intra=0 则立即连发(供测试快速收敛)。返回注入的明文字节数。
// 填充走 PaddingStreamID,客户端读循环静默丢弃。
func (d *downlinkShaper) injectToward(e *h2engine.Engine, maxRecords int, intra time.Duration) int {
	if !d.enabled || d.ratioTarget <= 0 {
		return 0
	}
	up := d.upBytes.Load()
	if up == 0 {
		return 0
	}
	target := uint64(d.ratioTarget * float64(up))

	injected := 0
	for n := 0; n < maxRecords; n++ {
		if d.downBytes.Load() >= target {
			break
		}
		rec := int(d.targetSize()) // 逐条采样,保留尺寸分布
		if rec <= 0 {
			rec = minDownlinkRecord
		}
		if err := e.WritePadding(uint16(rec)); err != nil {
			break
		}
		d.recordDown(rec)
		injected += rec
		if intra > 0 && n < maxRecords-1 {
			time.Sleep(intra)
		}
	}
	return injected
}

// burstRecords 返回本次突发应注入的记录数:按缺口估算,但受 maxBurst 上限约束,
// 使突发既能在高吞吐下跟上,又不至于单次灌入过量。
func (d *downlinkShaper) burstRecords() int {
	up := d.upBytes.Load()
	target := uint64(d.ratioTarget * float64(up))
	down := d.downBytes.Load()
	if down >= target {
		return 0
	}
	rec := int(d.targetSize())
	if rec <= 0 {
		rec = minDownlinkRecord
	}
	want := int((target - down + uint64(rec) - 1) / uint64(rec))
	capRec := d.maxBurst / rec
	if capRec < 1 {
		capRec = 1
	}
	if want > capRec {
		want = capRec
	}
	return want
}

// sampleIntra 返回突发内记录间延迟。优先用 profile 的突发内节奏,
// 否则回退到小幅随机(100µs–1ms)。
func (d *downlinkShaper) sampleIntra() time.Duration {
	if d.prof != nil {
		if delay := d.prof.RecordDelay(); delay > 0 {
			return delay
		}
	}
	return 100*time.Microsecond + time.Duration(rand.Int63n(int64(900*time.Microsecond)))
}

// runInjector 在后台按真实下载的突发结构注水,直到 done 关闭:
// 落后时连发一个突发(突发内 µs 级间隔),然后等待一个突发间 gap;
// 已达标时则按较长的空闲间隔轻探,避免恒定速率/零间隔的注入时序指纹。
//
// 注意:节奏越真实(intra 越大),注入速率上限越低;极高吞吐 + 高等级
// (max)下可能无法完全补满目标比——这是"时序真实性 vs 比值激进度"的固有权衡。
func (d *downlinkShaper) runInjector(e *h2engine.Engine, done <-chan struct{}) {
	if !d.enabled || d.ratioTarget <= 0 {
		return
	}
	behindGap, idleGap := d.minInterval, d.maxInterval
	if behindGap <= 0 || idleGap <= behindGap {
		behindGap, idleGap = governorMinInterval, governorMaxInterval
	}
	for {
		if !d.needsFill() {
			select {
			case <-done:
				return
			case <-time.After(idleGap):
			}
			continue
		}
		d.injectToward(e, d.burstRecords(), d.sampleIntra())
		// 突发间隔:仍落后则用较短 gap 追赶,已达标则用较长"思考时间"。
		gap := behindGap
		if !d.needsFill() {
			gap = idleGap
		}
		select {
		case <-done:
			return
		case <-time.After(gap):
		}
	}
}
