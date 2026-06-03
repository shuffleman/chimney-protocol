// Package profile implements traffic profile modeling and pacing (Part III §4).
//
// The profile captures the observable characteristics of real HTTPS traffic
// to a whitelisted site. The pacing engine then shapes Chimney tunnel traffic
// to match this profile.
//
// Profile model:
//
//	ProfileModel {
//	    size_dist:       distribution of TLS record sizes
//	    burst_size_dist: distribution of burst lengths (number of records per burst)
//	    intra_burst_seq: pacing between records within a burst
//	    gap_dist:        distribution of gaps between bursts ("think time")
//	    dir_ratio:       ratio of uplink vs downlink records
//	}
//
// The profile is calibrated once per site from pcap captures of real browser
// sessions (Appendix B). See CalibrateFromPcap for the calibration procedure.
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
	// DefaultBursts is the default number of bursts for the shaping window.
	DefaultBursts = 10

	// DefaultRecordsPerBurst is the default number of records per burst.
	DefaultRecordsPerBurst = 5

	// DefaultIntraBurstDelay is the default delay between records in a burst.
	DefaultIntraBurstDelay = 1 * time.Millisecond

	// DefaultInterBurstGap is the default gap between bursts.
	DefaultInterBurstGap = 10 * time.Millisecond
)

// SizeDistribution models the distribution of TLS record sizes.
// Uses a histogram with log-normal-like properties (typical for HTTPS).
type SizeDistribution struct {
	// Min and Max record sizes (plaintext, before encryption overhead).
	Min uint16 `json:"min"`
	Max uint16 `json:"max"`

	// Mean and StdDev of the log-normal distribution.
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`

	// Histogram buckets for empirical distribution (optional, for precision).
	Buckets []SizeBucket `json:"buckets,omitempty"`
}

// SizeBucket is a histogram bucket for record sizes.
type SizeBucket struct {
	Size  uint16  `json:"size"`
	Count uint32  `json:"count"`
	Prob  float64 `json:"prob"` // Normalized probability
}

// Sample draws a random record size from the distribution.
func (sd *SizeDistribution) Sample() uint16 {
	if len(sd.Buckets) > 0 {
		// Use empirical histogram
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

	// Use log-normal approximation
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

// BurstDistribution models the distribution of burst sizes (records per burst).
type BurstDistribution struct {
	// Min and Max records per burst.
	Min uint16 `json:"min"`
	Max uint16 `json:"max"`

	// Mean and StdDev for the distribution.
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
}

// Sample draws a random burst length from the distribution.
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

// GapDistribution models the distribution of gaps between bursts (think time).
type GapDistribution struct {
	// Min and Max gap duration.
	Min time.Duration `json:"min"`
	Max time.Duration `json:"max"`

	// Mean and StdDev in milliseconds.
	MeanMs   float64 `json:"mean_ms"`
	StdDevMs float64 `json:"std_dev_ms"`
}

// Sample draws a random gap duration from the distribution.
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

// DirectionRatio controls the uplink/downlink record ratio.
type DirectionRatio struct {
	// UplinkRatio is the fraction of records going client→relay.
	// Range [0, 1]. DownlinkRatio = 1 - UplinkRatio.
	UplinkRatio float64 `json:"uplink_ratio"`
}

// IsUplink returns true for an uplink record based on the ratio.
func (dr *DirectionRatio) IsUplink() bool {
	return rand.Float64() < dr.UplinkRatio
}

// IntraBurstPacing controls timing between records within a burst.
type IntraBurstPacing struct {
	// Min and Max delay between consecutive records.
	Min time.Duration `json:"min"`
	Max time.Duration `json:"max"`

	// Mean and StdDev in microseconds.
	MeanUs   float64 `json:"mean_us"`
	StdDevUs float64 `json:"std_dev_us"`
}

// Sample draws a random intra-burst pacing delay.
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

// Model represents the complete traffic profile for a site.
type Model struct {
	// SiteName identifies which site this profile is for.
	SiteName string `json:"site_name"`

	// SizeDist is the record size distribution.
	SizeDist *SizeDistribution `json:"size_dist"`

	// BurstDist is the burst size distribution.
	BurstDist *BurstDistribution `json:"burst_dist"`

	// GapDist is the inter-burst gap distribution.
	GapDist *GapDistribution `json:"gap_dist"`

	// DirRatio controls uplink/downlink mixing.
	DirRatio *DirectionRatio `json:"dir_ratio"`

	// IntraBurstPacing controls within-burst timing.
	IntraBurstPacing *IntraBurstPacing `json:"intra_burst_pacing"`

	// CalibratedAt records when this profile was last calibrated.
	CalibratedAt time.Time `json:"calibrated_at"`
}

// DefaultModel returns a conservative default profile.
// This is used when no calibrated profile is available.
func DefaultModel() *Model {
	return &Model{
		SiteName: "default",
		SizeDist: &SizeDistribution{
			Min:    128,
			Max:    16384,
			Mean:   8.0, // ~3KB median for log-normal
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

// SaveToFile saves the profile model to a JSON file.
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

// LoadModelFromFile loads a profile model from a JSON file.
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

// RecordSize returns a target record size for the next record.
func (m *Model) RecordSize() uint16 {
	if m.SizeDist == nil {
		return 1024
	}
	return m.SizeDist.Sample()
}

// BurstLength returns the number of records in the next burst.
func (m *Model) BurstLength() uint16 {
	if m.BurstDist == nil {
		return 5
	}
	return m.BurstDist.Sample()
}

// BurstGap returns the gap duration before the next burst.
func (m *Model) BurstGap() time.Duration {
	if m.GapDist == nil {
		return 10 * time.Millisecond
	}
	return m.GapDist.Sample()
}

// RecordDelay returns the delay before the next record within a burst.
func (m *Model) RecordDelay() time.Duration {
	if m.IntraBurstPacing == nil {
		return 500 * time.Microsecond
	}
	return m.IntraBurstPacing.Sample()
}

// IsUplink returns true if the next record should be uplink.
func (m *Model) IsUplink() bool {
	if m.DirRatio == nil {
		return rand.Float64() < 0.4
	}
	return m.DirRatio.IsUplink()
}

// CalibrateFromPcap calibrates a profile model from pcap analysis data.
// This is a placeholder for the actual pcap parsing logic.
// In production, this would parse pcap files and extract the distributions.
//
// The calibration procedure (Appendix B):
//  1. Capture HTTPS traffic to the site using a real browser (uTLS-matched)
//  2. Extract TLS record sizes, timing, and directions
//  3. Fit distributions to the observed data
//  4. Store alongside the SETTINGS snapshot
func CalibrateFromPcap(siteName string, recordSizes []uint16, burstSizes []uint16, gaps []time.Duration) *Model {
	m := &Model{
		SiteName:     siteName,
		CalibratedAt: time.Now(),
	}

	// Fit size distribution
	if len(recordSizes) > 0 {
		m.SizeDist = fitSizeDistribution(recordSizes)
	}

	// Fit burst distribution
	if len(burstSizes) > 0 {
		m.BurstDist = fitBurstDistribution(burstSizes)
	}

	// Fit gap distribution
	if len(gaps) > 0 {
		m.GapDist = fitGapDistribution(gaps)
	}

	// Default direction ratio (typically ~40% uplink for web browsing)
	m.DirRatio = &DirectionRatio{UplinkRatio: 0.4}

	// Default intra-burst pacing
	m.IntraBurstPacing = &IntraBurstPacing{
		Min:      100 * time.Microsecond,
		Max:      5 * time.Millisecond,
		MeanUs:   500,
		StdDevUs: 300,
	}

	return m
}

// fitSizeDistribution fits a size distribution from observed data.
func fitSizeDistribution(sizes []uint16) *SizeDistribution {
	if len(sizes) == 0 {
		return nil
	}

	// Compute min, max, mean, stddev on log-transformed sizes
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

	// Build histogram buckets
	bucketMap := make(map[uint16]uint32)
	for _, s := range sizes {
		// Round to nearest 256-byte bucket
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

// fitBurstDistribution fits a burst size distribution.
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

// fitGapDistribution fits a gap distribution.
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

// Pacer implements traffic pacing according to a profile model.
type Pacer struct {
	model *Model

	// Control channels
	stopCh chan struct{}
	doneCh chan struct{}

	// Callback for when a record should be sent
	recordCallback func(size uint16, isUplink bool)
}

// NewPacer creates a new pacer with the given model and callback.
func NewPacer(model *Model, recordCallback func(size uint16, isUplink bool)) *Pacer {
	return &Pacer{
		model:          model,
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
		recordCallback: recordCallback,
	}
}

// Start begins the pacing loop.
func (p *Pacer) Start() {
	go p.loop()
}

// Stop stops the pacing loop.
func (p *Pacer) Stop() {
	close(p.stopCh)
	<-p.doneCh
}

// loop runs the pacing algorithm (§4.2):
//
//	loop:
//	  burst_len ~ burst_size_dist
//	  repeat burst_len:
//	     target ~ size_dist; assemble tunnel|padding to target, seal record, send
//	     sleep(intra_burst_pacing)
//	  gap ~ gap_dist; sleep(gap)
//	  schedule direction per dir_ratio
func (p *Pacer) loop() {
	defer close(p.doneCh)

	for {
		select {
		case <-p.stopCh:
			return
		default:
		}

		// Determine burst length
		burstLen := p.model.BurstLength()

		// Send burst
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

			// Intra-burst pacing
			if i < burstLen-1 { // No delay after last record
				delay := p.model.RecordDelay()
				time.Sleep(delay)
			}
		}

		// Inter-burst gap
		gap := p.model.BurstGap()
		select {
		case <-p.stopCh:
			return
		case <-time.After(gap):
		}
	}
}

// ShapingWindow represents a window of shaped traffic.
// Used during the initial TLS-in-TLS fingerprint elimination phase (§3).
type ShapingWindow struct {
	// NumRecords is the number of records to shape (default ~10).
	NumRecords int

	// Model is the traffic profile to follow.
	Model *Model
}

// DefaultShapingWindow returns a default shaping window for fingerprint elimination.
func DefaultShapingWindow(model *Model) *ShapingWindow {
	return &ShapingWindow{
		NumRecords: 10,
		Model:      model,
	}
}

// NextRecordSize returns the target size for the next record in the shaping window.
func (sw *ShapingWindow) NextRecordSize() uint16 {
	return sw.Model.RecordSize()
}
