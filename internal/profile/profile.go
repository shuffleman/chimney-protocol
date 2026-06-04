// Package profile 实现流量配置文件的建模和调速（第三部分 §4）。
//
// 配置文件捕获到白名单站点的真实 HTTPS 流量的可观测特征。
// 调速引擎随后将 Chimney 隧道流量塑形以匹配此配置文件。
//
// 配置文件模型：
//
//	ProfileModel {
//	    size_dist:       TLS 记录大小的分布
//	    burst_size_dist: 突发长度的分布（每次突发的记录数）
//	    intra_burst_seq: 突发内记录间的调速
//	    gap_dist:        突发之间间隔的分布（“思考时间”）
//	    dir_ratio:       上行与下行记录的比例
//	}
//
// 配置文件通过真实浏览器会话的 pcap 捕获（附录 B）为每个站点校准一次。
// 参见 CalibrateFromPcap 了解校准过程。
package profile

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"
)

const (
	// DefaultBursts 是塑形窗口的默认突发数。
	DefaultBursts = 10

	// DefaultRecordsPerBurst 是每次突发的默认记录数。
	DefaultRecordsPerBurst = 5

	// DefaultIntraBurstDelay 是突发内记录间的默认延迟。
	DefaultIntraBurstDelay = 1 * time.Millisecond

	// DefaultInterBurstGap 是突发之间的默认间隔。
	DefaultInterBurstGap = 10 * time.Millisecond
)

// SizeDistribution 模拟 TLS 记录大小的分布。
// 使用具有对数正态特性的直方图（HTTPS 典型特征）。
type SizeDistribution struct {
	// Min 和 Max 记录大小（明文，加密开销前）。
	Min uint16 `json:"min"`
	Max uint16 `json:"max"`

	// Mean 和 StdDev 为对数正态分布的参数。
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`

	// Histogram 桶，用于经验分布（可选，提高精度）。
	Buckets []SizeBucket `json:"buckets,omitempty"`
}

// SizeBucket 是记录大小的直方图桶。
type SizeBucket struct {
	Size  uint16  `json:"size"`
	Count uint32  `json:"count"`
	Prob  float64 `json:"prob"` // 归一化概率
}

// Sample 从分布中随机抽取一个记录大小。
func (sd *SizeDistribution) Sample() uint16 {
	if len(sd.Buckets) > 0 {
		// 使用经验直方图
		r := rand.Float64()
		cumsum := 0.0
		for _, b := range sd.Buckets {
			cumsum += b.Prob
			if r <= cumsum {
				return b.Size
			}
		}
		return sd.Buckets[len(sd.Buckets)-1].Size
	}

	// 使用对数正态近似
	sample := sd.Mean + sd.StdDev*rand.NormFloat64()
	size := uint16(math.Exp(sample))
	if size < sd.Min {
		size = sd.Min
	}
	if size > sd.Max {
		size = sd.Max
	}
	return size
}

// BurstDistribution 模拟突发大小的分布（每次突发的记录数）。
type BurstDistribution struct {
	// Min 和 Max 每次突发的记录数。
	Min uint16 `json:"min"`
	Max uint16 `json:"max"`

	// Mean 和 StdDev 为分布的参数。
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
}

// Sample 从分布中随机抽取一个突发长度。
func (bd *BurstDistribution) Sample() uint16 {
	sample := bd.Mean + bd.StdDev*rand.NormFloat64()
	length := uint16(sample)
	if length < bd.Min {
		length = bd.Min
	}
	if length > bd.Max {
		length = bd.Max
	}
	return length
}

// GapDistribution 模拟突发之间间隔的分布（思考时间）。
type GapDistribution struct {
	// Min 和 Max 间隔持续时间。
	Min time.Duration `json:"min"`
	Max time.Duration `json:"max"`

	// Mean 和 StdDev，以毫秒为单位。
	MeanMs   float64 `json:"mean_ms"`
	StdDevMs float64 `json:"std_dev_ms"`
}

// Sample 从分布中随机抽取一个间隔持续时间。
func (gd *GapDistribution) Sample() time.Duration {
	sample := gd.MeanMs + gd.StdDevMs*rand.NormFloat64()
	ms := int64(sample)
	if ms < gd.Min.Milliseconds() {
		ms = gd.Min.Milliseconds()
	}
	if ms > gd.Max.Milliseconds() {
		ms = gd.Max.Milliseconds()
	}
	return time.Duration(ms) * time.Millisecond
}

// DirectionRatio 控制上行/下行记录比例。
type DirectionRatio struct {
	// UplinkRatio 是客户端→中继的记录比例。
	// 范围 [0, 1]。DownlinkRatio = 1 - UplinkRatio。
	UplinkRatio float64 `json:"uplink_ratio"`
}

// IsUplink 根据比例返回是否为上行记录。
func (dr *DirectionRatio) IsUplink() bool {
	return rand.Float64() < dr.UplinkRatio
}

// IntraBurstPacing 控制突发内记录间的时序。
type IntraBurstPacing struct {
	// Min 和 Max 连续记录间的延迟。
	Min time.Duration `json:"min"`
	Max time.Duration `json:"max"`

	// Mean 和 StdDev，以微秒为单位。
	MeanUs   float64 `json:"mean_us"`
	StdDevUs float64 `json:"std_dev_us"`
}

// Sample 随机抽取一个突发内调速延迟。
func (ibp *IntraBurstPacing) Sample() time.Duration {
	sample := ibp.MeanUs + ibp.StdDevUs*rand.NormFloat64()
	us := int64(sample)
	if us < ibp.Min.Microseconds() {
		us = ibp.Min.Microseconds()
	}
	if us > ibp.Max.Microseconds() {
		us = ibp.Max.Microseconds()
	}
	return time.Duration(us) * time.Microsecond
}

// Model 表示一个站点的完整流量配置文件。
type Model struct {
	// SiteName 标识此配置文件对应的站点。
	SiteName string `json:"site_name"`

	// SizeDist 是记录大小分布。
	SizeDist *SizeDistribution `json:"size_dist"`

	// BurstDist 是突发大小分布。
	BurstDist *BurstDistribution `json:"burst_dist"`

	// GapDist 是突发间间隔分布。
	GapDist *GapDistribution `json:"gap_dist"`

	// DirRatio 控制上行/下行混合。
	DirRatio *DirectionRatio `json:"dir_ratio"`

	// IntraBurstPacing 控制突发内时序。
	IntraBurstPacing *IntraBurstPacing `json:"intra_burst_pacing"`

	// CalibratedAt 记录此配置文件上次校准的时间。
	CalibratedAt time.Time `json:"calibrated_at"`
}

// DefaultModel 返回一个保守的默认配置文件。
// 当没有可用的校准配置文件时使用。
func DefaultModel() *Model {
	return &Model{
		SiteName: "default",
		SizeDist: &SizeDistribution{
			Min:    128,
			Max:    16384,
			Mean:   8.0, // 对数正态 ~3KB 中位数
			StdDev: 1.2,
		},
		BurstDist: &BurstDistribution{
			Min:    2,
			Max:    20,
			Mean:   6,
			StdDev: 2,
		},
		GapDist: &GapDistribution{
			Min:      5 * time.Millisecond,
			Max:      200 * time.Millisecond,
			MeanMs:   30,
			StdDevMs: 15,
		},
		DirRatio: &DirectionRatio{
			UplinkRatio: 0.4,
		},
		IntraBurstPacing: &IntraBurstPacing{
			Min:      100 * time.Microsecond,
			Max:      5 * time.Millisecond,
			MeanUs:   500,
			StdDevUs: 300,
		},
		CalibratedAt: time.Now(),
	}
}

// SaveToFile 将配置文件模型保存到 JSON 文件。
func (m *Model) SaveToFile(path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("profile: failed to marshal model: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("profile: failed to write model file: %w", err)
	}
	return nil
}

// LoadModelFromFile 从 JSON 文件加载配置文件模型。
func LoadModelFromFile(path string) (*Model, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile: failed to read model file: %w", err)
	}

	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("profile: failed to parse model JSON: %w", err)
	}
	return &m, nil
}

// RecordSize 返回下一个记录的目标记录大小。
func (m *Model) RecordSize() uint16 {
	if m.SizeDist == nil {
		return 1024
	}
	return m.SizeDist.Sample()
}

// BurstLength 返回下一个突发中的记录数。
func (m *Model) BurstLength() uint16 {
	if m.BurstDist == nil {
		return 5
	}
	return m.BurstDist.Sample()
}

// BurstGap 返回下一个突发之前的间隔持续时间。
func (m *Model) BurstGap() time.Duration {
	if m.GapDist == nil {
		return 10 * time.Millisecond
	}
	return m.GapDist.Sample()
}

// RecordDelay 返回突发内下一个记录之前的延迟。
func (m *Model) RecordDelay() time.Duration {
	if m.IntraBurstPacing == nil {
		return 500 * time.Microsecond
	}
	return m.IntraBurstPacing.Sample()
}

// IsUplink 返回下一个记录是否应为上行。
func (m *Model) IsUplink() bool {
	if m.DirRatio == nil {
		return rand.Float64() < 0.4
	}
	return m.DirRatio.IsUplink()
}

// CalibrateFromPcap 从 pcap 分析数据校准配置文件模型。
// 这是实际 pcap 解析逻辑的占位符。
// 生产中，这将解析 pcap 文件并提取分布。
//
// 校准过程（附录 B）：
//  1. 使用真实浏览器（与 uTLS 匹配）捕获到站点的 HTTPS 流量
//  2. 提取 TLS 记录大小、时序和方向
//  3. 将分布拟合到观测数据
//  4. 与 SETTINGS 快照一起存储
func CalibrateFromPcap(siteName string, recordSizes []uint16, burstSizes []uint16, gaps []time.Duration) *Model {
	m := &Model{
		SiteName:     siteName,
		CalibratedAt: time.Now(),
	}

	// 拟合大小分布
	if len(recordSizes) > 0 {
		m.SizeDist = fitSizeDistribution(recordSizes)
	}

	// 拟合突发分布
	if len(burstSizes) > 0 {
		m.BurstDist = fitBurstDistribution(burstSizes)
	}

	// 拟合间隔分布
	if len(gaps) > 0 {
		m.GapDist = fitGapDistribution(gaps)
	}

	// 默认方向比例（网页浏览通常约 40% 上行）
	m.DirRatio = &DirectionRatio{UplinkRatio: 0.4}

	// 默认突发内调速
	m.IntraBurstPacing = &IntraBurstPacing{
		Min:      100 * time.Microsecond,
		Max:      5 * time.Millisecond,
		MeanUs:   500,
		StdDevUs: 300,
	}

	return m
}

// fitSizeDistribution 从观测数据拟合大小分布。
func fitSizeDistribution(sizes []uint16) *SizeDistribution {
	if len(sizes) == 0 {
		return nil
	}

	// 计算对数变换后大小的最小值、最大值、均值、标准差
	min := sizes[0]
	max := sizes[0]
	var sum float64
	logs := make([]float64, len(sizes))
	for i, s := range sizes {
		if s < min {
			min = s
		}
		if s > max {
			max = s
		}
		logs[i] = math.Log(float64(s))
		sum += logs[i]
	}
	mean := sum / float64(len(sizes))

	var sumSq float64
	for _, l := range logs {
		diff := l - mean
		sumSq += diff * diff
	}
	stddev := math.Sqrt(sumSq / float64(len(sizes)))

	// 构建直方图桶
	bucketMap := make(map[uint16]uint32)
	for _, s := range sizes {
		// 四舍五入到最近的 256 字节桶
		bucket := (s + 128) / 256 * 256
		if bucket < 256 {
			bucket = 256
		}
		bucketMap[bucket]++
	}

	buckets := make([]SizeBucket, 0, len(bucketMap))
	total := uint32(len(sizes))
	for size, count := range bucketMap {
		buckets = append(buckets, SizeBucket{
			Size:  size,
			Count: count,
			Prob:  float64(count) / float64(total),
		})
	}

	return &SizeDistribution{
		Min:     min,
		Max:     max,
		Mean:    mean,
		StdDev:  stddev,
		Buckets: buckets,
	}
}

// fitBurstDistribution 拟合突发大小分布。
func fitBurstDistribution(bursts []uint16) *BurstDistribution {
	if len(bursts) == 0 {
		return nil
	}

	min := bursts[0]
	max := bursts[0]
	var sum float64
	for _, b := range bursts {
		if b < min {
			min = b
		}
		if b > max {
			max = b
		}
		sum += float64(b)
	}
	mean := sum / float64(len(bursts))

	var sumSq float64
	for _, b := range bursts {
		diff := float64(b) - mean
		sumSq += diff * diff
	}
	stddev := math.Sqrt(sumSq / float64(len(bursts)))

	return &BurstDistribution{
		Min:    min,
		Max:    max,
		Mean:   mean,
		StdDev: stddev,
	}
}

// fitGapDistribution 拟合间隔分布。
func fitGapDistribution(gaps []time.Duration) *GapDistribution {
	if len(gaps) == 0 {
		return nil
	}

	min := gaps[0]
	max := gaps[0]
	var sum float64
	for _, g := range gaps {
		if g < min {
			min = g
		}
		if g > max {
			max = g
		}
		sum += float64(g.Milliseconds())
	}
	mean := sum / float64(len(gaps))

	var sumSq float64
	for _, g := range gaps {
		diff := float64(g.Milliseconds()) - mean
		sumSq += diff * diff
	}
	stddev := math.Sqrt(sumSq / float64(len(gaps)))

	return &GapDistribution{
		Min:      min,
		Max:      max,
		MeanMs:   mean,
		StdDevMs: stddev,
	}
}

// Pacer 根据配置文件模型实现流量调速。
type Pacer struct {
	model *Model

	// 控制通道
	stopCh chan struct{}
	doneCh chan struct{}

	// 发送记录时的回调
	recordCallback func(size uint16, isUplink bool)
}

// NewPacer 使用给定的模型和回调创建一个新的调速器。
func NewPacer(model *Model, recordCallback func(size uint16, isUplink bool)) *Pacer {
	return &Pacer{
		model:          model,
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
		recordCallback: recordCallback,
	}
}

// Start 启动调速循环。
func (p *Pacer) Start() {
	go p.loop()
}

// Stop 停止调速循环。
func (p *Pacer) Stop() {
	close(p.stopCh)
	<-p.doneCh
}

// loop 运行调速算法（§4.2）：
//
//	loop:
//	  burst_len ~ burst_size_dist
//	  repeat burst_len:
//	     target ~ size_dist; 组装隧道|填充至 target, 密封记录, 发送
//	     sleep(intra_burst_pacing)
//	  gap ~ gap_dist; sleep(gap)
//	  按 dir_ratio 调度方向
func (p *Pacer) loop() {
	defer close(p.doneCh)

	for {
		select {
		case <-p.stopCh:
			return
		default:
		}

		// 确定突发长度
		burstLen := p.model.BurstLength()

		// 发送突发
		for i := uint16(0); i < burstLen; i++ {
			select {
			case <-p.stopCh:
				return
			default:
			}

			targetSize := p.model.RecordSize()
			isUplink := p.model.IsUplink()

			if p.recordCallback != nil {
				p.recordCallback(targetSize, isUplink)
			}

			// 突发内调速
			if i < burstLen-1 { // 最后一个记录后无延迟
				delay := p.model.RecordDelay()
				time.Sleep(delay)
			}
		}

		// 突发间间隔
		gap := p.model.BurstGap()
		select {
		case <-p.stopCh:
			return
		case <-time.After(gap):
		}
	}
}

// ShapingWindow 表示一个塑形流量窗口。
// 在初始 TLS-in-TLS 指纹消除阶段使用（§3）。
type ShapingWindow struct {
	// NumRecords 是塑形的记录数（默认 ~10）。
	NumRecords int

	// Model 是要遵循的流量配置文件。
	Model *Model
}

// DefaultShapingWindow 返回用于指纹消除的默认塑形窗口。
func DefaultShapingWindow(model *Model) *ShapingWindow {
	return &ShapingWindow{
		NumRecords: 10,
		Model:      model,
	}
}

// NextRecordSize 返回塑形窗口中下一个记录的目标大小。
func (sw *ShapingWindow) NextRecordSize() uint16 {
	return sw.Model.RecordSize()
}
