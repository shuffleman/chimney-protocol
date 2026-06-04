// cmd/calibrate 是用于校准站点流量配置文件的工具。
//
// 用法：
//
//	calibrate -pcap capture.pcap -site example.com -output profiles/
//
// 该工具分析真实 HTTPS 流量的 pcap 抓包文件，并生成：
//  1. 该站点的 SETTINGS 快照
//  2. 流量配置文件模型（大小/突发/间隔/方向分布）
//
// 两个输出对于正确的流量整形都是必需的。
//
// 对于 SETTINGS 提取，该工具支持 NSS SSLKEYLOGFILE 格式
// 用于解密 TLS 流量：
//
//	calibrate -pcap capture.pcap -site example.com -keylog sslkeylog.txt
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/h2engine"
	"github.com/shuffleman/chimney-protocol/internal/pcap"
	"github.com/shuffleman/chimney-protocol/internal/profile"
)

func main() {
	var (
		pcapFile     = flag.String("pcap", "", "Path to pcap capture file")
		siteName     = flag.String("site", "", "Site name (e.g., example.com)")
		outputDir    = flag.String("output", "profiles", "Output directory for profiles")
		settingsOnly = flag.Bool("settings-only", false, "Only extract SETTINGS")
		keylogFile   = flag.String("keylog", "", "NSS SSLKEYLOGFILE for TLS decryption")
		serverPort   = flag.Int("port", 443, "Server port to filter (default 443)")
	)
	flag.Parse()

	if *pcapFile == "" || *siteName == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -pcap <file> -site <name> [-output <dir>] [-keylog <file>]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Printf("Calibrating site: %s\n", *siteName)
	fmt.Printf("Pcap file: %s\n", *pcapFile)

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=== Phase 1: Extracting SETTINGS ===")
	settings, err := extractSettingsFromPcap(*pcapFile, uint16(*serverPort), *keylogFile)
	if err != nil {
		fmt.Printf("Warning: Could not extract SETTINGS from pcap: %v\n", err)
		fmt.Println("Using default SETTINGS. Run with actual capture for better results.")
		settings = h2engine.DefaultSettings()
	}

	settingsPath := filepath.Join(*outputDir, *siteName+".settings.json")
	if err := saveSettings(settings, settingsPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save SETTINGS: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SETTINGS saved to: %s\n", settingsPath)

	if *settingsOnly {
		fmt.Println("\nDone (settings-only mode).")
		return
	}

	fmt.Println("\n=== Phase 2: Extracting Traffic Profile ===")
	model, err := extractProfileFromPcap(*pcapFile, *siteName, uint16(*serverPort))
	if err != nil {
		fmt.Printf("Warning: Could not extract profile from pcap: %v\n", err)
		fmt.Println("Using default profile.")
		model = profile.DefaultModel()
		model.SiteName = *siteName
	}

	profilePath := filepath.Join(*outputDir, *siteName+".profile.json")
	if err := model.SaveToFile(profilePath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save profile: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Profile saved to: %s\n", profilePath)

	fmt.Println("\n=== Calibration Complete ===")
	fmt.Printf("Site: %s\n", *siteName)
	fmt.Printf("SETTINGS: %s\n", settingsPath)
	fmt.Printf("Profile:  %s\n", profilePath)
	fmt.Println("\nAdd to intent.yaml:")
	fmt.Printf(`  %s:
    sni: %s
    description: "Calibrated site"
    settings_snapshot:
      HEADER_TABLE_SIZE: %d
      ENABLE_PUSH: %d
      MAX_CONCURRENT_STREAMS: %d
      INITIAL_WINDOW_SIZE: %d
      MAX_FRAME_SIZE: %d
      MAX_HEADER_LIST_SIZE: %d
`, *siteName, *siteName,
		*settings.HeaderTableSize, *settings.EnablePush,
		*settings.MaxConcurrentStreams, *settings.InitialWindowSize,
		*settings.MaxFrameSize, *settings.MaxHeaderListSize)
}

// extractSettingsFromPcap 从 pcap 文件中提取 HTTP/2 SETTINGS。
//
// 策略（按优先级顺序）：
//  1. 如果提供了 keylog 文件，尝试解密并解析 H2 帧
//  2. 启发式方法：分析早期应用数据记录的大小来推测 SETTINGS
//  3. 回退到默认值
func extractSettingsFromPcap(pcapFile string, serverPort uint16, keylogFile string) (*h2engine.Settings, error) {
	fs, err := pcap.ReassembleStreams(pcapFile, serverPort)
	if err != nil {
		return nil, fmt.Errorf("reassemble streams: %w", err)
	}

	baseTime := time.Now()
	if len(fs.ClientTimestamps) > 0 {
		baseTime = fs.ClientTimestamps[0]
	}

	// 从两个方向提取 TLS 记录
	clientRecords := pcap.ExtractTLSRecords(fs.ClientToServer, pcap.DirClientToServer, baseTime, fs.ClientTimestamps)
	_ = pcap.ExtractTLSRecords(fs.ServerToClient, pcap.DirServerToClient, baseTime, fs.ServerTimestamps)

	// 查找客户端应用数据记录（握手后）
	var appDataRecords []pcap.TLSRecord
	for _, rec := range clientRecords {
		if rec.ContentType == pcap.TLSRecordApplicationData {
			appDataRecords = append(appDataRecords, rec)
		}
	}

	// 如果有 keylog，尝试解密
	if keylogFile != "" && len(appDataRecords) > 0 {
		settings, err := extractSettingsWithKeylog(fs, appDataRecords, keylogFile)
		if err == nil {
			return settings, nil
		}
		fmt.Printf("Keylog decryption failed (%v), falling back to heuristic.\n", err)
	}

	// 启发式方法：根据记录大小估算
	return heuristicSettings(appDataRecords), nil
}

// extractSettingsWithKeylog 尝试解密 TLS 并解析 H2 SETTINGS。
func extractSettingsWithKeylog(fs *pcap.FilteredStream, appDataRecords []pcap.TLSRecord, keylogFile string) (*h2engine.Settings, error) {
	entries, err := pcap.ParseNSSKeyLog(keylogFile)
	if err != nil {
		return nil, fmt.Errorf("parse keylog: %w", err)
	}
	_ = entries

	// 从 ClientHello 中提取 ClientRandom
	clientRandom, err := findClientRandom(fs.ClientToServer)
	if err != nil {
		return nil, fmt.Errorf("find ClientRandom: %w", err)
	}
	_ = clientRandom
	_ = appDataRecords

	// 完整的 TLS 1.3 解密需要实现 HKDF 密钥调度。
	// 目前，这是一个前瞻性钩子。
	return nil, fmt.Errorf("TLS decryption not yet implemented: %d keylog entries loaded, ClientRandom extracted", len(entries))
}

// findClientRandom 扫描客户端→服务器流中的 ClientHello 并提取 ClientRandom。
func findClientRandom(stream []byte) ([]byte, error) {
	records := pcap.ExtractTLSRecords(stream, pcap.DirClientToServer, time.Now(), nil)
	for _, rec := range records {
		if rec.ContentType != pcap.TLSRecordHandshake {
			continue
		}
		cr, err := pcap.ExtractClientRandom(rec.Payload)
		if err == nil {
			return cr, nil
		}
	}
	return nil, fmt.Errorf("no ClientHello found in stream")
}

// heuristicSettings 从应用数据记录大小估算 H2 SETTINGS。
//
// 第一个应用数据记录（握手后）通常包含：
//
//	H2 前言（24 字节）+ SETTINGS 帧头（9 字节）+ 设置参数
//
// TLS 1.2 GCM：记录开销 = 8（显式 nonce）+ 16（标签）= 24 字节
// TLS 1.3：记录开销 = 1（内部内容类型）+ 16（标签）= 17 字节
//
// 因此：明文 = 记录长度 - 开销
//
//	settings_params_len = 明文 - 24（前言）- 9（帧头）
//	num_settings = settings_params_len / 6
func heuristicSettings(records []pcap.TLSRecord) *h2engine.Settings {
	if len(records) == 0 {
		fmt.Println("No app-data records found; using defaults.")
		return h2engine.DefaultSettings()
	}

	// 查看早期记录
	var sizes []int
	for i, rec := range records {
		if i >= 5 {
			break
		}
		plainSize := pcap.EstimatePlaintextSize(rec.Length, rec.Version)
		sizes = append(sizes, plainSize)
		fmt.Printf("  Early record %d: TLS length=%d, est. plaintext=%d bytes\n", i+1, rec.Length, plainSize)
	}

	// 第一个记录应包含 H2 前言 + SETTINGS
	if len(sizes) > 0 && sizes[0] > 0 {
		settingsPayloadLen := sizes[0] - 24 - 9 // preface - frame header
		if settingsPayloadLen > 0 && settingsPayloadLen%6 == 0 {
			numSettings := settingsPayloadLen / 6
			fmt.Printf("  Estimated settings count: %d (from %d byte payload)\n", numSettings, settingsPayloadLen)

			if numSettings == 6 {
				fmt.Println("  → Looks like standard 6-parameter SETTINGS. Using defaults — verify with keylog for accuracy.")
			} else if numSettings == 5 {
				fmt.Printf("  → Detected %d SETTINGS params (unusual). Using defaults — verify with keylog.\n", numSettings)
			} else {
				fmt.Printf("  → Detected %d SETTINGS params. Using defaults.\n", numSettings)
			}
		}
	}

	fmt.Println("Heuristic extraction: using default SETTINGS (use -keylog for precise extraction).")
	return h2engine.DefaultSettings()
}

// extractProfileFromPcap 从 pcap 文件中提取流量配置文件。
//
// 这不需要 TLS 解密——它分析明文 TLS 记录头
// 的大小、时序和方向。
func extractProfileFromPcap(pcapFile, siteName string, serverPort uint16) (*profile.Model, error) {
	fs, err := pcap.ReassembleStreams(pcapFile, serverPort)
	if err != nil {
		return nil, fmt.Errorf("reassemble streams: %w", err)
	}

	if len(fs.ClientToServer) == 0 && len(fs.ServerToClient) == 0 {
		return nil, fmt.Errorf("no TCP payload data found for port %d", serverPort)
	}

	baseTime := time.Now()
	if len(fs.ClientTimestamps) > 0 {
		baseTime = fs.ClientTimestamps[0]
	}

	// 从两个方向提取 TLS 记录
	clientRecords := pcap.ExtractTLSRecords(fs.ClientToServer, pcap.DirClientToServer, baseTime, fs.ClientTimestamps)
	serverRecords := pcap.ExtractTLSRecords(fs.ServerToClient, pcap.DirServerToClient, baseTime, fs.ServerTimestamps)

	// 筛选出应用数据记录（对流量配置重要）
	var appDataRecords []pcap.TLSRecord
	for _, rec := range clientRecords {
		if rec.ContentType == pcap.TLSRecordApplicationData {
			appDataRecords = append(appDataRecords, rec)
		}
	}
	for _, rec := range serverRecords {
		if rec.ContentType == pcap.TLSRecordApplicationData {
			appDataRecords = append(appDataRecords, rec)
		}
	}

	if len(appDataRecords) == 0 {
		fmt.Println("No application_data records in capture; using defaults.")
		return profile.DefaultModel(), nil
	}

	// 按时间戳排序
	sort.Slice(appDataRecords, func(i, j int) bool {
		return appDataRecords[i].Timestamp.Before(appDataRecords[j].Timestamp)
	})

	fmt.Printf("Total application_data records: %d\n", len(appDataRecords))
	fmt.Printf("  Uplink: %d, Downlink: %d\n",
		countDirection(appDataRecords, pcap.DirClientToServer),
		countDirection(appDataRecords, pcap.DirServerToClient))

	// 提取记录大小
	var sizes []uint16
	var uplinkSizes []uint16
	for _, rec := range appDataRecords {
		sizes = append(sizes, rec.Length)
		if rec.Direction == pcap.DirClientToServer {
			uplinkSizes = append(uplinkSizes, rec.Length)
		}
	}

	// 检测突发：连续记录之间间隔小于阈值
	burstThreshold := 50 * time.Millisecond
	bursts := detectBursts(appDataRecords, burstThreshold)

	var burstSizes []uint16
	for _, b := range bursts {
		burstSizes = append(burstSizes, uint16(len(b)))
	}

	// 计算突发间间隔
	gaps := computeInterBurstGaps(appDataRecords, burstThreshold)

	fmt.Printf("Detected %d bursts (threshold=%v)\n", len(bursts), burstThreshold)
	if len(burstSizes) > 0 {
		fmt.Printf("  Burst sizes: min=%d max=%d mean=%.1f\n",
			minU16(burstSizes), maxU16(burstSizes), meanU16(burstSizes))
	}
	if len(gaps) > 0 {
		fmt.Printf("  Gaps: min=%v max=%v mean=%v\n",
			minDuration(gaps), maxDuration(gaps), meanDuration(gaps))
	}

	// 计算方向比例
	uplinkRatio := float64(len(uplinkSizes)) / float64(len(appDataRecords))
	fmt.Printf("Uplink ratio: %.2f\n", uplinkRatio)

	// 拟合突发内间隔
	var intraBurstGaps []time.Duration
	for _, burst := range bursts {
		for i := 1; i < len(burst); i++ {
			gap := burst[i].Timestamp.Sub(burst[i-1].Timestamp)
			intraBurstGaps = append(intraBurstGaps, gap)
		}
	}

	model := &profile.Model{
		SiteName:     siteName,
		CalibratedAt: time.Now(),
		SizeDist:     fitSizeDist(sizes),
		BurstDist:    fitBurstDist(burstSizes),
		GapDist:      fitGapDist(gaps),
		DirRatio:     &profile.DirectionRatio{UplinkRatio: uplinkRatio},
	}

	if len(intraBurstGaps) > 0 {
		model.IntraBurstPacing = fitIntraBurstPacing(intraBurstGaps)
	} else {
		model.IntraBurstPacing = &profile.IntraBurstPacing{
			Min: 100 * time.Microsecond, Max: 5 * time.Millisecond,
			MeanUs: 500, StdDevUs: 300,
		}
	}

	return model, nil
}

// burst 表示时间窗口内的一组连续记录。
type burst []pcap.TLSRecord

// detectBursts 将记录分组为突发，其中记录间间隔小于阈值。
func detectBursts(records []pcap.TLSRecord, threshold time.Duration) []burst {
	if len(records) == 0 {
		return nil
	}

	var bursts []burst
	current := burst{records[0]}

	for i := 1; i < len(records); i++ {
		gap := records[i].Timestamp.Sub(records[i-1].Timestamp)
		if gap < threshold {
			current = append(current, records[i])
		} else {
			bursts = append(bursts, current)
			current = burst{records[i]}
		}
	}
	bursts = append(bursts, current)
	return bursts
}

// computeInterBurstGaps 计算突发之间的间隔。
func computeInterBurstGaps(records []pcap.TLSRecord, threshold time.Duration) []time.Duration {
	var gaps []time.Duration
	for i := 1; i < len(records); i++ {
		gap := records[i].Timestamp.Sub(records[i-1].Timestamp)
		if gap >= threshold {
			gaps = append(gaps, gap)
		}
	}
	return gaps
}

// countDirection 统计匹配某个方向的记录数。
func countDirection(records []pcap.TLSRecord, dir int) int {
	n := 0
	for _, r := range records {
		if r.Direction == dir {
			n++
		}
	}
	return n
}

// fitSizeDist 根据大小列表拟合 SizeDistribution。
func fitSizeDist(sizes []uint16) *profile.SizeDistribution {
	if len(sizes) == 0 {
		return &profile.SizeDistribution{Min: 128, Max: 16384, Mean: 8.0, StdDev: 1.2}
	}

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

	// 构建直方图桶（256 字节粒度）
	bucketMap := make(map[uint16]uint32)
	for _, s := range sizes {
		bucket := (s + 128) / 256 * 256
		if bucket < 256 {
			bucket = 256
		}
		bucketMap[bucket]++
	}

	buckets := make([]profile.SizeBucket, 0, len(bucketMap))
	total := uint32(len(sizes))
	for size, count := range bucketMap {
		buckets = append(buckets, profile.SizeBucket{
			Size:  size,
			Count: count,
			Prob:  float64(count) / float64(total),
		})
	}

	return &profile.SizeDistribution{
		Min:     min,
		Max:     max,
		Mean:    mean,
		StdDev:  stddev,
		Buckets: buckets,
	}
}

// fitBurstDist 拟合 BurstDistribution。
func fitBurstDist(burstSizes []uint16) *profile.BurstDistribution {
	if len(burstSizes) == 0 {
		return &profile.BurstDistribution{Min: 2, Max: 20, Mean: 6, StdDev: 2}
	}

	min := burstSizes[0]
	max := burstSizes[0]
	var sum float64
	for _, b := range burstSizes {
		if b < min {
			min = b
		}
		if b > max {
			max = b
		}
		sum += float64(b)
	}

	mean := sum / float64(len(burstSizes))
	var sumSq float64
	for _, b := range burstSizes {
		diff := float64(b) - mean
		sumSq += diff * diff
	}
	stddev := math.Sqrt(sumSq / float64(len(burstSizes)))

	return &profile.BurstDistribution{
		Min:    min,
		Max:    max,
		Mean:   mean,
		StdDev: stddev,
	}
}

// fitGapDist 拟合 GapDistribution。
func fitGapDist(gaps []time.Duration) *profile.GapDistribution {
	if len(gaps) == 0 {
		return &profile.GapDistribution{
			Min: 5 * time.Millisecond, Max: 200 * time.Millisecond,
			MeanMs: 30, StdDevMs: 15,
		}
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

	return &profile.GapDistribution{
		Min:      min,
		Max:      max,
		MeanMs:   mean,
		StdDevMs: stddev,
	}
}

// fitIntraBurstPacing 根据突发内记录间隔拟合 IntraBurstPacing。
func fitIntraBurstPacing(gaps []time.Duration) *profile.IntraBurstPacing {
	if len(gaps) == 0 {
		return &profile.IntraBurstPacing{
			Min: 100 * time.Microsecond, Max: 5 * time.Millisecond,
			MeanUs: 500, StdDevUs: 300,
		}
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
		sum += float64(g.Microseconds())
	}

	mean := sum / float64(len(gaps))
	var sumSq float64
	for _, g := range gaps {
		diff := float64(g.Microseconds()) - mean
		sumSq += diff * diff
	}
	stddev := math.Sqrt(sumSq / float64(len(gaps)))

	return &profile.IntraBurstPacing{
		Min:      min,
		Max:      max,
		MeanUs:   mean,
		StdDevUs: stddev,
	}
}

// 辅助函数。
func minU16(vals []uint16) uint16 {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func maxU16(vals []uint16) uint16 {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func meanU16(vals []uint16) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += float64(v)
	}
	return sum / float64(len(vals))
}

func minDuration(vals []time.Duration) time.Duration {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func maxDuration(vals []time.Duration) time.Duration {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func meanDuration(vals []time.Duration) time.Duration {
	if len(vals) == 0 {
		return 0
	}
	var sum int64
	for _, v := range vals {
		sum += int64(v)
	}
	return time.Duration(sum / int64(len(vals)))
}

// saveSettings 将 SETTINGS 保存到 JSON 文件。
func saveSettings(settings *h2engine.Settings, path string) error {
	data := map[string]interface{}{
		"HEADER_TABLE_SIZE":      *settings.HeaderTableSize,
		"ENABLE_PUSH":            *settings.EnablePush,
		"MAX_CONCURRENT_STREAMS": *settings.MaxConcurrentStreams,
		"INITIAL_WINDOW_SIZE":    *settings.InitialWindowSize,
		"MAX_FRAME_SIZE":         *settings.MaxFrameSize,
		"MAX_HEADER_LIST_SIZE":   *settings.MaxHeaderListSize,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, jsonData, 0644)
}
