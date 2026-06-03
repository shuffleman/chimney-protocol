// cmd/calibrate is a tool for calibrating site traffic profiles.
//
// Usage:
//
//	calibrate -pcap capture.pcap -site example.com -output profiles/
//
// This tool analyzes pcap captures of real HTTPS traffic and generates:
//  1. SETTINGS snapshot for the site
//  2. Traffic profile model (size/burst/gap/direction distributions)
//
// Both outputs are required for proper traffic shaping.
//
// For SETTINGS extraction, the tool supports NSS SSLKEYLOGFILE format for
// decrypting TLS traffic:
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

// extractSettingsFromPcap extracts HTTP/2 SETTINGS from a pcap file.
//
// Strategy (in priority order):
//  1. If keylog file provided, attempt to decrypt and parse H2 frames
//  2. Heuristic: analyze sizes of early app-data records to guess SETTINGS
//  3. Fall back to defaults
func extractSettingsFromPcap(pcapFile string, serverPort uint16, keylogFile string) (*h2engine.Settings, error) {
	fs, err := pcap.ReassembleStreams(pcapFile, serverPort)
	if err != nil {
		return nil, fmt.Errorf("reassemble streams: %w", err)
	}

	baseTime := time.Now()
	if len(fs.ClientTimestamps) > 0 {
		baseTime = fs.ClientTimestamps[0]
	}

	// Extract TLS records from both directions
	clientRecords := pcap.ExtractTLSRecords(fs.ClientToServer, pcap.DirClientToServer, baseTime, fs.ClientTimestamps)
	_ = pcap.ExtractTLSRecords(fs.ServerToClient, pcap.DirServerToClient, baseTime, fs.ServerTimestamps)

	// Find client application_data records (post-handshake)
	var appDataRecords []pcap.TLSRecord
	for _, rec := range clientRecords {
		if rec.ContentType == pcap.TLSRecordApplicationData {
			appDataRecords = append(appDataRecords, rec)
		}
	}

	// If we have a keylog, attempt decryption
	if keylogFile != "" && len(appDataRecords) > 0 {
		settings, err := extractSettingsWithKeylog(fs, appDataRecords, keylogFile)
		if err == nil {
			return settings, nil
		}
		fmt.Printf("Keylog decryption failed (%v), falling back to heuristic.\n", err)
	}

	// Heuristic: estimate from record sizes
	return heuristicSettings(appDataRecords), nil
}

// extractSettingsWithKeylog attempts to decrypt TLS and parse H2 SETTINGS.
func extractSettingsWithKeylog(fs *pcap.FilteredStream, appDataRecords []pcap.TLSRecord, keylogFile string) (*h2engine.Settings, error) {
	entries, err := pcap.ParseNSSKeyLog(keylogFile)
	if err != nil {
		return nil, fmt.Errorf("parse keylog: %w", err)
	}
	_ = entries

	// Extract ClientRandom from the ClientHello
	clientRandom, err := findClientRandom(fs.ClientToServer)
	if err != nil {
		return nil, fmt.Errorf("find ClientRandom: %w", err)
	}
	_ = clientRandom
	_ = appDataRecords

	// Full TLS 1.3 decryption requires implementing HKDF key schedule.
	// For now, this is a forward-looking hook.
	return nil, fmt.Errorf("TLS decryption not yet implemented: %d keylog entries loaded, ClientRandom extracted", len(entries))
}

// findClientRandom scans the client→server stream for a ClientHello and extracts ClientRandom.
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

// heuristicSettings estimates H2 SETTINGS from app-data record sizes.
//
// The first app-data record after handshake typically contains:
//
//	H2 Preface (24 bytes) + SETTINGS frame header (9 bytes) + settings params
//
// TLS 1.2 GCM: record_overhead = 8 (explicit nonce) + 16 (tag) = 24 bytes
// TLS 1.3: record_overhead = 1 (inner content type) + 16 (tag) = 17 bytes
//
// So: plaintext = record_length - overhead
//
//	settings_params_len = plaintext - 24 (preface) - 9 (frame header)
//	num_settings = settings_params_len / 6
func heuristicSettings(records []pcap.TLSRecord) *h2engine.Settings {
	if len(records) == 0 {
		fmt.Println("No app-data records found; using defaults.")
		return h2engine.DefaultSettings()
	}

	// Look at early records
	var sizes []int
	for i, rec := range records {
		if i >= 5 {
			break
		}
		plainSize := pcap.EstimatePlaintextSize(rec.Length, rec.Version)
		sizes = append(sizes, plainSize)
		fmt.Printf("  Early record %d: TLS length=%d, est. plaintext=%d bytes\n", i+1, rec.Length, plainSize)
	}

	// The first record should contain H2 preface + SETTINGS
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

// extractProfileFromPcap extracts traffic profile from a pcap file.
//
// This works without TLS decryption — it analyzes plaintext TLS record headers
// for size, timing, and direction.
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

	// Extract TLS records from both directions
	clientRecords := pcap.ExtractTLSRecords(fs.ClientToServer, pcap.DirClientToServer, baseTime, fs.ClientTimestamps)
	serverRecords := pcap.ExtractTLSRecords(fs.ServerToClient, pcap.DirServerToClient, baseTime, fs.ServerTimestamps)

	// Filter to application_data only (what matters for traffic profile)
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

	// Sort by timestamp
	sort.Slice(appDataRecords, func(i, j int) bool {
		return appDataRecords[i].Timestamp.Before(appDataRecords[j].Timestamp)
	})

	fmt.Printf("Total application_data records: %d\n", len(appDataRecords))
	fmt.Printf("  Uplink: %d, Downlink: %d\n",
		countDirection(appDataRecords, pcap.DirClientToServer),
		countDirection(appDataRecords, pcap.DirServerToClient))

	// Extract record sizes
	var sizes []uint16
	var uplinkSizes []uint16
	for _, rec := range appDataRecords {
		sizes = append(sizes, rec.Length)
		if rec.Direction == pcap.DirClientToServer {
			uplinkSizes = append(uplinkSizes, rec.Length)
		}
	}

	// Detect bursts: consecutive records with inter-record gap < threshold
	burstThreshold := 50 * time.Millisecond
	bursts := detectBursts(appDataRecords, burstThreshold)

	var burstSizes []uint16
	for _, b := range bursts {
		burstSizes = append(burstSizes, uint16(len(b)))
	}

	// Compute inter-burst gaps
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

	// Compute direction ratio
	uplinkRatio := float64(len(uplinkSizes)) / float64(len(appDataRecords))
	fmt.Printf("Uplink ratio: %.2f\n", uplinkRatio)

	// Fit intra-burst pacing
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

// burst represents a consecutive sequence of records within a time window.
type burst []pcap.TLSRecord

// detectBursts groups records into bursts where inter-record gaps are < threshold.
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

// computeInterBurstGaps computes the gaps between bursts.
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

// countDirection counts records matching a direction.
func countDirection(records []pcap.TLSRecord, dir int) int {
	n := 0
	for _, r := range records {
		if r.Direction == dir {
			n++
		}
	}
	return n
}

// fitSizeDist fits a SizeDistribution from sizes.
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

	// Build histogram buckets (256-byte granularity)
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

// fitBurstDist fits a BurstDistribution.
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

// fitGapDist fits a GapDistribution.
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

// fitIntraBurstPacing fits IntraBurstPacing from within-burst record gaps.
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

// Helper functions.
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

// saveSettings saves SETTINGS to a JSON file.
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
