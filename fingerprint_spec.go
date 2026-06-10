package chimney

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// 精确指纹校准(pcap)
//
// 通用预设(chrome/firefox/…)只能"逼近"真实浏览器,扩展数量、顺序、ALPN、
// JA3 仍有代码级偏差(见 stealth_detection_report.md)。精确校准的做法:
// 用 cmd/calibrate 从真实浏览器访问目标站点的 pcap 中提取 ClientHello 原始
// 字节,持久化;连接时用 uTLS Fingerprinter 重建 ClientHelloSpec,以
// HelloCustom + ApplyPreset 复刻这条真实 ClientHello。
//
// 持久化采用原始字节(hex):ClientHelloSpec 含接口类型扩展,不便序列化;
// 且 uTLS 文档明确警告 spec 的切片/指针跨连接共享 —— 因此每条连接都从
// 原始字节重建一份独立 spec(见 buildClientHelloSpec 的调用点)。

// loadClientHelloRaw 读取 .clienthello 文件(hex 编码的完整 TLS 握手记录),
// 返回原始字节。忽略所有空白与换行。
func loadClientHelloRaw(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("chimney: read client_hello_file: %w", err)
	}
	compact := strings.Join(strings.Fields(string(data)), "")
	raw, err := hex.DecodeString(compact)
	if err != nil {
		return nil, fmt.Errorf("chimney: client_hello_file must be hex: %w", err)
	}
	if len(raw) < 6 || raw[0] != 0x16 || raw[5] != 0x01 {
		return nil, fmt.Errorf("chimney: client_hello_file is not a TLS ClientHello handshake record")
	}
	return raw, nil
}

// buildClientHelloSpec 从原始 ClientHello 记录字节重建一份 uTLS ClientHelloSpec。
// 每条连接调用一次以获得独立 spec(避免跨连接共享扩展状态)。
//
// 启用 AllowBluntMimicry:未识别的扩展按原样复刻,最大化对真实捕获的兼容与
// 还原度(已知扩展仍按各自类型正确处理)。
func buildClientHelloSpec(raw []byte) (*utls.ClientHelloSpec, error) {
	fp := &utls.Fingerprinter{AllowBluntMimicry: true}
	spec, err := fp.FingerprintClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("chimney: fingerprint client hello: %w", err)
	}
	return spec, nil
}
