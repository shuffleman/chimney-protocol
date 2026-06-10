// Package pcap 为校准工具提供最小的 pcap 文件解析器。
//
// 它处理：
//   - PCAP 全局头和包迭代
//   - IPv4 + TCP 头解析
//   - TCP 流重组（单方向，有序）
//   - TLS 记录提取（仅明文头 — 不解密）
//   - NSS SSLKEYLOGFILE 解析用于可选解密
package pcap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// pcap 全局头的链路类型值。
const (
	LinkTypeEthernet = 1
)

// 常见 EtherType。
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD
)

// IP 协议号。
const (
	IPProtocolTCP = 6
)

// TLS 记录内容类型和版本。
const (
	TLSRecordChangeCipherSpec = 0x14
	TLSRecordAlert            = 0x15
	TLSRecordHandshake        = 0x16
	TLSRecordApplicationData  = 0x17

	TLSVersion12 = 0x0303
	TLSVersion13 = 0x0304
)

// PcapGlobalHeader 是 pcap 文件中的 24 字节全局头。
type PcapGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

// PcapPacketHeader 是 16 字节的每包头部。
type PcapPacketHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// Timestamp 返回包的时间戳。
func (ph *PcapPacketHeader) Timestamp() time.Time {
	return time.Unix(int64(ph.TsSec), int64(ph.TsUsec)*1000)
}

// TCPPacket 表示从 pcap 包解析的 TCP 段。
type TCPPacket struct {
	Timestamp time.Time
	SrcIP     [4]byte
	DstIP     [4]byte
	SrcPort   uint16
	DstPort   uint16
	SeqNum    uint32
	Payload   []byte
	Direction int // 0 = 客户端→服务器, 1 = 服务器→客户端
}

// TLSRecord 表示从 TCP 流中提取的 TLS 记录。
type TLSRecord struct {
	ContentType uint8
	Version     uint16
	Length      uint16
	Payload     []byte // 密文副本（无解密密钥）
	Timestamp   time.Time
	Direction   int // 0 = 客户端→服务器（上行）, 1 = 服务器→客户端（下行）
}

// HandshakeMessage 表示解析后的 TLS 握手消息。
type HandshakeMessage struct {
	Type    uint8
	Length  uint32 // 24-bit
	Payload []byte
}

// Parser 读取并解析 pcap 文件。
type Parser struct {
	file        *os.File
	reader      *bufio.Reader
	byteOrder   binary.ByteOrder
	globalHdr   PcapGlobalHeader
	packetCount int
}

// Open 打开一个 pcap 文件进行读取。
func Open(path string) (*Parser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("pcap: open file: %w", err)
	}

	reader := bufio.NewReader(f)

	// 读取全局头
	var hdr [24]byte
	if _, err := io.ReadFull(reader, hdr[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("pcap: read global header: %w", err)
	}

	gh := PcapGlobalHeader{
		MagicNumber:  binary.BigEndian.Uint32(hdr[0:4]),
		VersionMajor: binary.BigEndian.Uint16(hdr[4:6]),
		VersionMinor: binary.BigEndian.Uint16(hdr[6:8]),
		ThisZone:     int32(binary.BigEndian.Uint32(hdr[8:12])),
		SigFigs:      binary.BigEndian.Uint32(hdr[12:16]),
		SnapLen:      binary.BigEndian.Uint32(hdr[16:20]),
		Network:      binary.BigEndian.Uint32(hdr[20:24]),
	}

	// 从幻数确定字节序
	var byteOrder binary.ByteOrder
	switch gh.MagicNumber {
	case 0xa1b2c3d4:
		byteOrder = binary.BigEndian
	case 0xd4c3b2a1:
		byteOrder = binary.LittleEndian
		// 以小端序重新读取字段
		gh.MagicNumber = binary.LittleEndian.Uint32(hdr[0:4])
		gh.VersionMajor = binary.LittleEndian.Uint16(hdr[4:6])
		gh.VersionMinor = binary.LittleEndian.Uint16(hdr[6:8])
		gh.ThisZone = int32(binary.LittleEndian.Uint32(hdr[8:12]))
		gh.SigFigs = binary.LittleEndian.Uint32(hdr[12:16])
		gh.SnapLen = binary.LittleEndian.Uint32(hdr[16:20])
		gh.Network = binary.LittleEndian.Uint32(hdr[20:24])
	default:
		f.Close()
		return nil, fmt.Errorf("pcap: unknown magic number 0x%08x (not a pcap file or pcap-ng)", gh.MagicNumber)
	}

	return &Parser{
		file:      f,
		reader:    reader,
		byteOrder: byteOrder,
		globalHdr: gh,
	}, nil
}

// Close 关闭 pcap 文件。
func (p *Parser) Close() error {
	return p.file.Close()
}

// Network 返回链路层类型。
func (p *Parser) Network() uint32 {
	return p.globalHdr.Network
}

// NextPacket 从 pcap 文件读取下一个包。
// 读取完毕时返回 nil, io.EOF。
func (p *Parser) NextPacket() (*PcapPacketHeader, []byte, error) {
	var phdr [16]byte
	_, err := io.ReadFull(p.reader, phdr[:])
	if err != nil {
		return nil, nil, err
	}

	ph := &PcapPacketHeader{
		TsSec:   p.byteOrder.Uint32(phdr[0:4]),
		TsUsec:  p.byteOrder.Uint32(phdr[4:8]),
		InclLen: p.byteOrder.Uint32(phdr[8:12]),
		OrigLen: p.byteOrder.Uint32(phdr[12:16]),
	}

	payload := make([]byte, ph.InclLen)
	if _, err := io.ReadFull(p.reader, payload); err != nil {
		return nil, nil, err
	}

	p.packetCount++
	return ph, payload, nil
}

// ParseTCPPacket 将原始包解析为 TCPPacket。
// 处理 Ethernet → IPv4 → TCP 分层。
func (p *Parser) ParseTCPPacket(ph *PcapPacketHeader, raw []byte) (*TCPPacket, error) {
	if p.globalHdr.Network != LinkTypeEthernet {
		return nil, fmt.Errorf("pcap: unsupported link type %d", p.globalHdr.Network)
	}

	if len(raw) < 14 {
		return nil, errors.New("pcap: packet too short for ethernet header")
	}

	etherType := binary.BigEndian.Uint16(raw[12:14])
	if etherType != EtherTypeIPv4 {
		return nil, fmt.Errorf("pcap: non-IPv4 ethertype 0x%04x", etherType)
	}

	ipStart := 14
	if len(raw) < ipStart+20 {
		return nil, errors.New("pcap: packet too short for IP header")
	}

	// 解析 IPv4 头
	versionIHL := raw[ipStart]
	ihl := (versionIHL & 0x0F) * 4 // IHL in 32-bit words
	protocol := raw[ipStart+9]

	if protocol != IPProtocolTCP {
		return nil, fmt.Errorf("pcap: non-TCP protocol %d", protocol)
	}

	var srcIP, dstIP [4]byte
	copy(srcIP[:], raw[ipStart+12:ipStart+16])
	copy(dstIP[:], raw[ipStart+16:ipStart+20])

	tcpStart := ipStart + int(ihl)
	if len(raw) < tcpStart+20 {
		return nil, errors.New("pcap: packet too short for TCP header")
	}

	srcPort := binary.BigEndian.Uint16(raw[tcpStart : tcpStart+2])
	dstPort := binary.BigEndian.Uint16(raw[tcpStart+2 : tcpStart+4])
	seqNum := binary.BigEndian.Uint32(raw[tcpStart+4 : tcpStart+8])
	dataOffset := (raw[tcpStart+12] >> 4) * 4

	payloadStart := tcpStart + int(dataOffset)
	payload := raw[payloadStart:]

	return &TCPPacket{
		Timestamp: ph.Timestamp(),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		SeqNum:    seqNum,
		Payload:   payload,
		Direction: 0,
	}, nil
}

// FilterTCP 按目标端口过滤包并返回解析后的 TCP 包。
func (p *Parser) FilterTCP(port uint16) ([]*TCPPacket, error) {
	var packets []*TCPPacket
	for {
		ph, raw, err := p.NextPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		tcp, err := p.ParseTCPPacket(ph, raw)
		if err != nil {
			continue // 跳过非 TCP 包
		}

		if tcp.DstPort == port || tcp.SrcPort == port {
			// 确定方向：发往端口的第一个包是客户端→服务器
			if tcp.DstPort == port {
				tcp.Direction = 0 // 客户端→服务器
			} else {
				tcp.Direction = 1 // 服务器→客户端
			}
			packets = append(packets, tcp)
		}
	}
	return packets, nil
}

// ExtractTLSRecords 解析重组后的 TCP 流并提取 TLS 记录。
// 流必须来自单一方向（客户端→服务器或服务器→客户端）。
func ExtractTLSRecords(stream []byte, direction int, baseTime time.Time, packetTimes []time.Time) []TLSRecord {
	var records []TLSRecord
	timeIdx := 0

	for len(stream) >= 5 {
		contentType := stream[0]
		version := binary.BigEndian.Uint16(stream[1:3])
		length := binary.BigEndian.Uint16(stream[3:5])

		// 合理性检查
		if length > 16384+256 { // 最大 TLS 记录为 16KB 加一些开销
			break
		}
		if contentType < 20 || contentType > 23 {
			// 不是有效的 TLS 记录 — 跳过一个字节重试
			stream = stream[1:]
			continue
		}

		if int(length)+5 > len(stream) {
			break // 不完整的记录
		}

		rec := TLSRecord{
			ContentType: contentType,
			Version:     version,
			Length:      length,
			Payload:     make([]byte, length),
			Direction:   direction,
		}
		copy(rec.Payload, stream[5:5+length])

		// 分配尽力而为的时间戳
		if timeIdx < len(packetTimes) {
			rec.Timestamp = packetTimes[timeIdx]
			timeIdx++
		} else {
			rec.Timestamp = baseTime
		}

		records = append(records, rec)
		stream = stream[5+length:]
	}

	return records
}

// ParseHandshakeMessage 从握手记录负载解析 TLS 握手消息。
func ParseHandshakeMessage(payload []byte) (*HandshakeMessage, error) {
	if len(payload) < 4 {
		return nil, errors.New("pcap: handshake message too short")
	}

	return &HandshakeMessage{
		Type:    payload[0],
		Length:  uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3]),
		Payload: payload[4:],
	}, nil
}

// 方向常量，用于 FilterDirection。
const (
	DirBoth = iota
	DirClientToServer
	DirServerToClient
)

// FilteredStream 保存按方向分离的重组 TCP 流。
type FilteredStream struct {
	ClientToServer []byte
	ServerToClient []byte

	// 数据到达时的时间戳（用于时序分析）
	ClientTimestamps []time.Time
	ServerTimestamps []time.Time

	// ServerPort 是服务器监听的端口
	ServerPort uint16
}

// ReassembleStreams 打开 pcap，过滤端口的 TCP 包，并按方向重组流。
// 这是一个简化版的重组，假设：
//   - 包按顺序到达（对抓取的 pcap 文件有效）
//   - 单一 TCP 连接（首次出现的五元组获胜）
func ReassembleStreams(pcapPath string, serverPort uint16) (*FilteredStream, error) {
	p, err := Open(pcapPath)
	if err != nil {
		return nil, err
	}
	defer p.Close()

	fs := &FilteredStream{
		ServerPort: serverPort,
	}

	var clientIP, serverIP [4]byte
	var clientPort, serverPortSeen uint16
	initialized := false

	for {
		ph, raw, err := p.NextPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		tcp, err := p.ParseTCPPacket(ph, raw)
		if err != nil {
			continue
		}

		// 按端口过滤
		if tcp.DstPort != serverPort && tcp.SrcPort != serverPort {
			continue
		}

		if !initialized {
			if tcp.DstPort == serverPort {
				clientIP = tcp.SrcIP
				serverIP = tcp.DstIP
				clientPort = tcp.SrcPort
				serverPortSeen = tcp.DstPort
			} else {
				clientIP = tcp.DstIP
				serverIP = tcp.SrcIP
				clientPort = tcp.DstPort
				serverPortSeen = tcp.SrcPort
			}
			initialized = true
		}

		// 检查此包是否属于我们的连接
		isClientToServer := tcp.SrcIP == clientIP && tcp.DstIP == serverIP &&
			tcp.SrcPort == clientPort && tcp.DstPort == serverPortSeen
		isServerToClient := tcp.SrcIP == serverIP && tcp.DstIP == clientIP &&
			tcp.SrcPort == serverPortSeen && tcp.DstPort == clientPort

		if isClientToServer && len(tcp.Payload) > 0 {
			fs.ClientToServer = append(fs.ClientToServer, tcp.Payload...)
			fs.ClientTimestamps = append(fs.ClientTimestamps, tcp.Timestamp)
		} else if isServerToClient && len(tcp.Payload) > 0 {
			fs.ServerToClient = append(fs.ServerToClient, tcp.Payload...)
			fs.ServerTimestamps = append(fs.ServerTimestamps, tcp.Timestamp)
		}
	}

	return fs, nil
}

// NSSKeyLog 表示解析后的 NSS SSLKEYLOGFILE 条目。
type NSSKeyLog struct {
	Label        string
	ClientRandom []byte
	Secret       []byte
}

// ParseNSSKeyLog 解析 NSS 风格的 SSLKEYLOGFILE。
// 格式：<Label> <ClientRandom_hex> <Secret_hex>
func ParseNSSKeyLog(path string) ([]NSSKeyLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []NSSKeyLog
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}

		var label string
		var clientRandomHex, secretHex string
		if _, err := fmt.Sscanf(line, "%s %s %s", &label, &clientRandomHex, &secretHex); err != nil {
			continue
		}

		clientRandom, err := hexDecode(clientRandomHex)
		if err != nil || len(clientRandom) != 32 {
			continue
		}
		secret, err := hexDecode(secretHex)
		if err != nil {
			continue
		}

		entries = append(entries, NSSKeyLog{
			Label:        label,
			ClientRandom: clientRandom,
			Secret:       secret,
		})
	}

	return entries, scanner.Err()
}

// hexDecode 将 hex 字符串解码为字节。
func hexDecode(s string) ([]byte, error) {
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		if _, err := fmt.Sscanf(s[i:i+2], "%02x", &b); err != nil {
			return nil, err
		}
		result[i/2] = b
	}
	return result, nil
}

// ExtractClientHelloRecord 从重组的客户端→服务器字节流中提取第一条 TLS
// 握手记录的完整原始字节(含 5 字节记录头)。返回的字节可直接传给
// uTLS Fingerprinter.FingerprintClientHello 以重建 ClientHelloSpec。
//
// 假定 ClientHello 位于单条 TLS 记录中(主流浏览器均如此)。
func ExtractClientHelloRecord(clientStream []byte) ([]byte, error) {
	if len(clientStream) < 5 {
		return nil, errors.New("pcap: stream too short for TLS record header")
	}
	if clientStream[0] != 0x16 { // handshake
		return nil, fmt.Errorf("pcap: first record is not handshake (content_type=0x%02x)", clientStream[0])
	}
	recLen := int(clientStream[3])<<8 | int(clientStream[4])
	if recLen == 0 {
		return nil, errors.New("pcap: empty handshake record")
	}
	total := 5 + recLen
	if len(clientStream) < total {
		return nil, fmt.Errorf("pcap: truncated handshake record (need %d bytes, have %d) — ClientHello may span multiple records", total, len(clientStream))
	}
	record := clientStream[:total]
	if record[5] != 0x01 { // ClientHello
		return nil, fmt.Errorf("pcap: first handshake message is not ClientHello (type=0x%02x)", record[5])
	}
	out := make([]byte, total)
	copy(out, record)
	return out, nil
}

// ExtractClientRandom 从重组的 ClientHello 字节中提取 ClientRandom。
func ExtractClientRandom(clientHelloPayload []byte) ([]byte, error) {
	hm, err := ParseHandshakeMessage(clientHelloPayload)
	if err != nil {
		return nil, err
	}
	if hm.Type != 0x01 {
		return nil, fmt.Errorf("pcap: expected ClientHello (0x01), got 0x%02x", hm.Type)
	}
	if len(hm.Payload) < 2+32 {
		return nil, errors.New("pcap: ClientHello body too short for random")
	}
	cr := make([]byte, 32)
	copy(cr, hm.Payload[2:34])
	return cr, nil
}

// TLS 不同版本和密码套件的开销估算。
const (
	// TLS 1.2 GCM 开销：8 字节显式 nonce + 16 字节标签。
	TLS12GCMOverhead = 24

	// TLS 1.3 开销：1 字节内部内容类型 + 16 字节标签。
	// 加上 5 字节外部记录头。
	TLS13Overhead = 17
)

// EstimatePlaintextSize 从 TLS 记录大小估算明文大小。
// 这是启发式的 — 实际开销取决于密码套件。
func EstimatePlaintextSize(recordLength uint16, version uint16) int {
	if version == TLSVersion13 {
		return int(recordLength) - TLS13Overhead
	}
	return int(recordLength) - TLS12GCMOverhead
}
