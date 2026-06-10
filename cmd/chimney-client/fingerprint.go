// Package main 实现 uTLS 指纹选择与轮换。
//
// -fingerprint 标志接受逗号分隔的指纹名称列表。
// 示例：
//
//	-fingerprint chrome                     （单个指纹）
//	-fingerprint chrome,firefox,safari      （在 3 种浏览器间轮换）
//	-fingerprint chrome-120,chrome-100      （在 Chrome 版本间轮换）
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// loadClientHelloRaw 读取精确指纹文件(hex 编码的完整 TLS ClientHello 记录),
// 返回原始字节。忽略空白与换行。
func loadClientHelloRaw(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client_hello_file: %w", err)
	}
	raw, err := hex.DecodeString(strings.Join(strings.Fields(string(data)), ""))
	if err != nil {
		return nil, fmt.Errorf("client_hello_file must be hex: %w", err)
	}
	if len(raw) < 6 || raw[0] != 0x16 || raw[5] != 0x01 {
		return nil, fmt.Errorf("client_hello_file is not a TLS ClientHello handshake record")
	}
	return raw, nil
}

// buildClientHelloSpec 从原始字节重建独立的 uTLS ClientHelloSpec(每连接调用一次,
// 避免跨连接共享扩展状态)。
func buildClientHelloSpec(raw []byte) (*utls.ClientHelloSpec, error) {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	spec, err := fp.FingerprintClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("fingerprint client hello: %w", err)
	}
	return spec, nil
}

// FingerprintRotator 循环遍历 uTLS ClientHelloID 列表。
// 可在多个连接间安全并发使用。
type FingerprintRotator struct {
	ids []utls.ClientHelloID
	cur int
	mu  sync.Mutex
}

// NewFingerprintRotator 从指纹名称列表创建轮换器。
// 每个名称可以是短别名（如"chrome"）或包含版本
// （如"chrome-120"、"firefox-105"）。
func NewFingerprintRotator(names []string) (*FingerprintRotator, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("at least one fingerprint name is required")
	}

	ids := make([]utls.ClientHelloID, 0, len(names))
	for _, name := range names {
		id, err := parseFingerprint(strings.TrimSpace(name))
		if err != nil {
			return nil, fmt.Errorf("invalid fingerprint %q: %w", name, err)
		}
		ids = append(ids, id)
	}

	return &FingerprintRotator{ids: ids}, nil
}

// Next 返回轮换中的下一个指纹。
func (r *FingerprintRotator) Next() utls.ClientHelloID {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.ids[r.cur]
	r.cur = (r.cur + 1) % len(r.ids)
	return id
}

// parseFingerprint 将名称字符串映射到 uTLS ClientHelloID。
func parseFingerprint(name string) (utls.ClientHelloID, error) {
	// 标准化：转小写，连字符转下划线
	normalized := strings.ToLower(name)

	switch normalized {
	// --- Chrome 变体 ---
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "chrome-58":
		return utls.HelloChrome_58, nil
	case "chrome-62":
		return utls.HelloChrome_62, nil
	case "chrome-70":
		return utls.HelloChrome_70, nil
	case "chrome-72":
		return utls.HelloChrome_72, nil
	case "chrome-83":
		return utls.HelloChrome_83, nil
	case "chrome-87":
		return utls.HelloChrome_87, nil
	case "chrome-96":
		return utls.HelloChrome_96, nil
	case "chrome-100":
		return utls.HelloChrome_100, nil
	case "chrome-102":
		return utls.HelloChrome_102, nil
	case "chrome-106":
		return utls.HelloChrome_106_Shuffle, nil
	case "chrome-120":
		return utls.HelloChrome_120, nil
	case "chrome-120-pq":
		return utls.HelloChrome_120_PQ, nil

	// --- Firefox 变体 ---
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "firefox-55":
		return utls.HelloFirefox_55, nil
	case "firefox-56":
		return utls.HelloFirefox_56, nil
	case "firefox-63":
		return utls.HelloFirefox_63, nil
	case "firefox-65":
		return utls.HelloFirefox_65, nil
	case "firefox-99":
		return utls.HelloFirefox_99, nil
	case "firefox-102":
		return utls.HelloFirefox_102, nil
	case "firefox-105":
		return utls.HelloFirefox_105, nil
	case "firefox-120":
		return utls.HelloFirefox_120, nil

	// --- Safari 变体 ---
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "safari-16":
		return utls.HelloSafari_16_0, nil

	// --- iOS 变体 ---
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "ios-11":
		return utls.HelloIOS_11_1, nil
	case "ios-12":
		return utls.HelloIOS_12_1, nil
	case "ios-13":
		return utls.HelloIOS_13, nil
	case "ios-14":
		return utls.HelloIOS_14, nil

	// --- Edge 变体 ---
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "edge-85":
		return utls.HelloEdge_85, nil
	case "edge-106":
		return utls.HelloEdge_106, nil

	// --- Android 变体 ---
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil

	// --- 国产浏览器 ---
	case "360":
		return utls.Hello360_Auto, nil
	case "360-7":
		return utls.Hello360_7_5, nil
	case "360-11":
		return utls.Hello360_11_0, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "qq-11":
		return utls.HelloQQ_11_1, nil

	// --- 随机化 ---
	case "randomized":
		return utls.HelloRandomized, nil
	case "randomized-alpn":
		return utls.HelloRandomizedALPN, nil
	case "randomized-noalpn":
		return utls.HelloRandomizedNoALPN, nil

	// --- Golang 变体 ---
	case "golang":
		return utls.HelloGolang, nil

	default:
		return utls.ClientHelloID{},
			fmt.Errorf("unknown fingerprint %q (available: chrome, firefox, safari, ios, edge, android, 360, qq, randomized, golang — with optional -version)", name)
	}
}

// FingerprintNames 返回一个逗号分隔的列表，用于标志默认值/用法。
func FingerprintNames(rotator *FingerprintRotator) string {
	if rotator == nil {
		return ""
	}
	names := make([]string, len(rotator.ids))
	for i, id := range rotator.ids {
		names[i] = fmt.Sprintf("%s:%s", id.Client, id.Version)
	}
	return strings.Join(names, ",")
}
