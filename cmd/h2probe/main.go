// cmd/h2probe — 实时 H2 SETTINGS 探测工具
//
// 连接到真实 HTTPS 服务器，完成 TLS+H2 握手，实时捕获
// 服务器的 SETTINGS（以及连接级 WINDOW_UPDATE）帧。
// 输出可直接粘贴到 intent.yaml 的 settings_snapshot 块，并可通过
// -update 标志原地更新文件。
//
// 用法：
//
//	h2probe -sni cloudflare.com,www.google.com
//	h2probe -file sites.txt -update config/intent.yaml
//	h2probe -sni www.cloudflare.com -timeout 15s -concurrency 3
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	h2Magic  = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	frameHdr = 9
)

// H2 帧类型常量。
const (
	typeSettings     = 0x4
	typeWindowUpdate = 0x8
	flagAck          = 0x1
)

// H2 SETTINGS 标识符常量。
const (
	idHeaderTableSize      = 0x1
	idEnablePush           = 0x2
	idMaxConcurrentStreams = 0x3
	idInitialWindowSize    = 0x4
	idMaxFrameSize         = 0x5
	idMaxHeaderListSize    = 0x6
)

var settingName = map[uint16]string{
	idHeaderTableSize:      "HEADER_TABLE_SIZE",
	idEnablePush:           "ENABLE_PUSH",
	idMaxConcurrentStreams: "MAX_CONCURRENT_STREAMS",
	idInitialWindowSize:    "INITIAL_WINDOW_SIZE",
	idMaxFrameSize:         "MAX_FRAME_SIZE",
	idMaxHeaderListSize:    "MAX_HEADER_LIST_SIZE",
}

// ProbeResult 保存一个 SNI 的原始探测结果。
type ProbeResult struct {
	SNI              string
	Settings         map[string]uint32 // SETTINGS key → value
	ConnectionWindow uint32            // stream-0 WINDOW_UPDATE increment, 0 if absent
	CapturedAt       time.Time
	Err              error
}

func main() {
	sniFlag := flag.String("sni", "", "Comma-separated list of SNIs to probe")
	fileFlag := flag.String("file", "", "File with SNIs (one per line)")
	updateFlag := flag.String("update", "", "Path to intent.yaml — update settings_snapshot in-place")
	timeoutFlag := flag.Duration("timeout", 10*time.Second, "Per-connection timeout")
	concFlag := flag.Int("concurrency", 5, "Parallel probes")
	portFlag := flag.Int("port", 443, "Target port")
	flag.Parse()

	var snis []string
	if *sniFlag != "" {
		for _, s := range strings.Split(*sniFlag, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				snis = append(snis, s)
			}
		}
	}
	if *fileFlag != "" {
		f, err := os.Open(*fileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open %s: %v\n", *fileFlag, err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			s := strings.TrimSpace(sc.Text())
			if s != "" && !strings.HasPrefix(s, "#") {
				snis = append(snis, s)
			}
		}
		f.Close()
	}
	if len(snis) == 0 {
		fmt.Fprintf(os.Stderr, "No SNIs specified. Use -sni or -file.\n")
		flag.Usage()
		os.Exit(1)
	}

	// 去重
	seen := make(map[string]bool, len(snis))
	var unique []string
	for _, s := range snis {
		if !seen[s] {
			seen[s] = true
			unique = append(unique, s)
		}
	}
	snis = unique

	// 使用有界并发运行探测
	results := make([]*ProbeResult, len(snis))
	sem := make(chan struct{}, *concFlag)
	var wg sync.WaitGroup
	for i, sni := range snis {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			fmt.Printf("probing %-40s ...\n", host)
			results[idx] = probe(host, *portFlag, *timeoutFlag)
		}(i, sni)
	}
	wg.Wait()

	// 打印结果
	fmt.Println()
	fmt.Println("=== Results ===")
	fmt.Println()

	var successCount int
	for _, r := range results {
		if r.Err != nil {
			fmt.Printf("  %-40s FAIL  %v\n", r.SNI, r.Err)
			continue
		}
		successCount++
		printYAMLBlock(r)
	}

	fmt.Printf("\n%d/%d probes succeeded.\n", successCount, len(results))

	// 如果请求，更新 intent.yaml
	if *updateFlag != "" {
		if err := updateIntentYAML(*updateFlag, results); err != nil {
			fmt.Fprintf(os.Stderr, "\nupdating %s: %v\n", *updateFlag, err)
			os.Exit(1)
		}
		fmt.Printf("\nUpdated %s with %d entries.\n", *updateFlag, successCount)
	}
}

// probe 连接到 host:port，完成 H2 握手，并捕获 SETTINGS。
func probe(sni string, port int, timeout time.Duration) *ProbeResult {
	r := &ProbeResult{SNI: sni, CapturedAt: time.Now()}

	addr := net.JoinHostPort(sni, strconv.Itoa(port))
	rawConn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		r.Err = fmt.Errorf("connect: %w", err)
		return r
	}
	defer rawConn.Close()
	rawConn.SetDeadline(time.Now().Add(timeout))

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: sni,
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		r.Err = fmt.Errorf("TLS handshake: %w", err)
		return r
	}

	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		r.Err = fmt.Errorf("server did not negotiate h2 (got %q)", tlsConn.ConnectionState().NegotiatedProtocol)
		return r
	}

	// 发送 H2 客户端前言（魔数 + 空 SETTINGS 帧）
	clientSettings := encodeSettings(nil, false) // 空 SETTINGS
	preface := append([]byte(h2Magic), clientSettings...)
	if _, err := tlsConn.Write(preface); err != nil {
		r.Err = fmt.Errorf("send preface: %w", err)
		return r
	}

	// 读取帧，直到获得服务器 SETTINGS（以及可选的 WINDOW_UPDATE）
	br := bufio.NewReaderSize(tlsConn, 64*1024)
	gotSettings := false
	for {
		fh, payload, err := readFrame(br)
		if err != nil {
			if gotSettings {
				break // already have what we need
			}
			r.Err = fmt.Errorf("read frame: %w", err)
			return r
		}

		switch fh.Type {
		case typeSettings:
			if fh.Flags&flagAck != 0 {
				continue // 跳过 ACK 帧
			}
			settings, err := decodeSettings(payload)
			if err != nil {
				r.Err = fmt.Errorf("decode SETTINGS: %w", err)
				return r
			}
			r.Settings = settings
			gotSettings = true

			// 发送 SETTINGS ACK
			ack := encodeSettings(nil, true)
			tlsConn.Write(ack)

		case typeWindowUpdate:
			if fh.StreamID == 0 && len(payload) == 4 {
				r.ConnectionWindow = binary.BigEndian.Uint32(payload) & 0x7FFFFFFF
			}

		default:
			// 忽略其他帧；HEADERS、GOAWAY 等。
		}

		// 在收到 SETTINGS + 1 个额外帧窗口后停止，或发送 ACK 后停止
		if gotSettings && r.ConnectionWindow != 0 {
			break
		}
		// 如果读取时间过长也停止（服务器可能不发送 WINDOW_UPDATE）
		if gotSettings {
			rawConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		}
	}

	if !gotSettings {
		r.Err = fmt.Errorf("no SETTINGS frame received")
	}
	return r
}

// frameHeader 是解析后的 H2 帧头。
type frameHeader struct {
	Length   uint32
	Type     uint8
	Flags    uint8
	StreamID uint32
}

func readFrame(r io.Reader) (*frameHeader, []byte, error) {
	hdr := make([]byte, frameHdr)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, nil, err
	}
	fh := &frameHeader{
		Length:   uint32(hdr[0])<<16 | uint32(hdr[1])<<8 | uint32(hdr[2]),
		Type:     hdr[3],
		Flags:    hdr[4],
		StreamID: binary.BigEndian.Uint32(hdr[5:9]) & 0x7FFFFFFF,
	}
	payload := make([]byte, fh.Length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, err
	}
	return fh, payload, nil
}

func decodeSettings(payload []byte) (map[string]uint32, error) {
	if len(payload)%6 != 0 {
		return nil, fmt.Errorf("SETTINGS payload not a multiple of 6 (got %d)", len(payload))
	}
	out := make(map[string]uint32)
	for i := 0; i+5 < len(payload); i += 6 {
		id := binary.BigEndian.Uint16(payload[i : i+2])
		val := binary.BigEndian.Uint32(payload[i+2 : i+6])
		if name, ok := settingName[id]; ok {
			out[name] = val
		} else {
			out[fmt.Sprintf("SETTING_0x%04X", id)] = val
		}
	}
	return out, nil
}

func encodeSettings(params map[string]uint32, ack bool) []byte {
	payload := make([]byte, 0, len(params)*6)
	for name, val := range params {
		for id, n := range settingName {
			if n == name {
				b := make([]byte, 6)
				binary.BigEndian.PutUint16(b[0:2], id)
				binary.BigEndian.PutUint32(b[2:6], val)
				payload = append(payload, b...)
				break
			}
		}
	}
	frame := make([]byte, frameHdr+len(payload))
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	frame[3] = typeSettings
	if ack {
		frame[4] = flagAck
	}
	// 流 ID = 0
	copy(frame[frameHdr:], payload)
	return frame
}

func printYAMLBlock(r *ProbeResult) {
	fmt.Printf("  %s:\n", r.SNI)
	fmt.Printf("    sni: %s\n", r.SNI)
	fmt.Printf("    description: \"Live-captured %s\"\n", r.CapturedAt.UTC().Format("2006-01-02"))
	fmt.Printf("    settings_snapshot:\n")
	printSetting(r.Settings, "HEADER_TABLE_SIZE", 4096)
	printSetting(r.Settings, "ENABLE_PUSH", 0)
	printSetting(r.Settings, "MAX_CONCURRENT_STREAMS", 100)
	printSetting(r.Settings, "INITIAL_WINDOW_SIZE", 65535)
	printSetting(r.Settings, "MAX_FRAME_SIZE", 16384)
	printSetting(r.Settings, "MAX_HEADER_LIST_SIZE", 0)
	if r.ConnectionWindow != 0 {
		fmt.Printf("    # connection_window_update: %d\n", r.ConnectionWindow)
	}
	fmt.Println()
}

func printSetting(m map[string]uint32, key string, defaultVal uint32) {
	if v, ok := m[key]; ok {
		fmt.Printf("      %s: %d\n", key, v)
	} else if defaultVal != 0 {
		fmt.Printf("      %s: %d  # default (not sent by server)\n", key, defaultVal)
	}
}

// IntentFile 是 intent.yaml 的磁盘结构。
type IntentFile struct {
	Version   int                     `yaml:"version"`
	UpdatedAt string                  `yaml:"updated_at,omitempty"`
	Entries   map[string]*IntentEntry `yaml:"entries"`
}

// IntentEntry 用于 YAML 往返的 whitelist.IntentEntry 镜像。
type IntentEntry struct {
	SNI              string                 `yaml:"sni"`
	Description      string                 `yaml:"description,omitempty"`
	SettingsSnapshot map[string]interface{} `yaml:"settings_snapshot,omitempty"`
	ProfileModel     map[string]interface{} `yaml:"profile_model,omitempty"`
}

func updateIntentYAML(path string, results []*ProbeResult) error {
	var file IntentFile

	// 加载现有文件（如果存在）
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(raw) > 0 {
		if err := yaml.Unmarshal(raw, &file); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if file.Entries == nil {
		file.Entries = make(map[string]*IntentEntry)
	}
	if file.Version == 0 {
		file.Version = 1
	}

	for _, r := range results {
		if r.Err != nil {
			continue
		}
		entry, exists := file.Entries[r.SNI]
		if !exists {
			entry = &IntentEntry{SNI: r.SNI}
			file.Entries[r.SNI] = entry
		}
		entry.SNI = r.SNI // 始终修正 sni 字段以匹配映射键
		entry.Description = fmt.Sprintf("Live-captured %s", r.CapturedAt.UTC().Format("2006-01-02"))

		snap := make(map[string]interface{}, len(r.Settings))
		for k, v := range r.Settings {
			snap[k] = v
		}
		// 填写服务器未发送的设置项的默认值
		defaults := map[string]uint32{
			"HEADER_TABLE_SIZE":      4096,
			"ENABLE_PUSH":            0,
			"MAX_CONCURRENT_STREAMS": 100,
			"INITIAL_WINDOW_SIZE":    65535,
			"MAX_FRAME_SIZE":         16384,
		}
		for k, v := range defaults {
			if _, ok := snap[k]; !ok {
				snap[k] = v
			}
		}
		entry.SettingsSnapshot = snap
	}

	file.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	out, err := yaml.Marshal(&file)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, out, 0644)
}
