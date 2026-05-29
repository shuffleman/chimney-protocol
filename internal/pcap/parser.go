// Package pcap provides a minimal pcap file parser for the calibrate tool.
//
// It handles:
//   - PCAP global header and packet iteration
//   - IPv4 + TCP header parsing
//   - TCP stream reassembly (single-direction, in-order)
//   - TLS record extraction (plaintext headers only — no decryption)
//   - NSS SSLKEYLOGFILE parsing for optional decryption
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

// LinkType values from pcap global header.
const (
	LinkTypeEthernet = 1
)

// Common EtherTypes.
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD
)

// IP protocol numbers.
const (
	IPProtocolTCP = 6
)

// TLS record content types and versions.
const (
	TLSRecordChangeCipherSpec = 0x14
	TLSRecordAlert            = 0x15
	TLSRecordHandshake        = 0x16
	TLSRecordApplicationData  = 0x17

	TLSVersion12 = 0x0303
	TLSVersion13 = 0x0304
)

// PcapGlobalHeader is the 24-byte global header in a pcap file.
type PcapGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

// PcapPacketHeader is the 16-byte per-packet header.
type PcapPacketHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// Timestamp returns the packet timestamp.
func (ph *PcapPacketHeader) Timestamp() time.Time {
	return time.Unix(int64(ph.TsSec), int64(ph.TsUsec)*1000)
}

// TCPPacket represents a parsed TCP segment from a pcap packet.
type TCPPacket struct {
	Timestamp  time.Time
	SrcIP      [4]byte
	DstIP      [4]byte
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	Payload    []byte
	Direction  int // 0 = client→server, 1 = server→client
}

// TLSRecord represents a TLS record extracted from TCP stream.
type TLSRecord struct {
	ContentType uint8
	Version     uint16
	Length      uint16
	Payload     []byte // Copy of ciphertext (no decryption key)
	Timestamp   time.Time
	Direction   int // 0 = client→server (uplink), 1 = server→client (downlink)
}

// HandshakeMessage represents a parsed TLS handshake message.
type HandshakeMessage struct {
	Type    uint8
	Length  uint32 // 24-bit
	Payload []byte
}

// Parser reads and parses a pcap file.
type Parser struct {
	file        *os.File
	reader      *bufio.Reader
	byteOrder   binary.ByteOrder
	globalHdr   PcapGlobalHeader
	packetCount int
}

// Open opens a pcap file for reading.
func Open(path string) (*Parser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("pcap: open file: %w", err)
	}

	reader := bufio.NewReader(f)

	// Read global header
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

	// Determine byte order from magic number
	var byteOrder binary.ByteOrder
	switch gh.MagicNumber {
	case 0xa1b2c3d4:
		byteOrder = binary.BigEndian
	case 0xd4c3b2a1:
		byteOrder = binary.LittleEndian
		// Re-read fields in little-endian
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

// Close closes the pcap file.
func (p *Parser) Close() error {
	return p.file.Close()
}

// Network returns the link layer type.
func (p *Parser) Network() uint32 {
	return p.globalHdr.Network
}

// NextPacket reads the next packet from the pcap file.
// Returns nil, io.EOF when done.
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

// ParseTCPPacket parses a raw packet into a TCPPacket.
// Handles Ethernet → IPv4 → TCP layering.
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

	// Parse IPv4 header
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

// FilterTCP filters packets by destination port and returns parsed TCP packets.
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
			continue // Skip non-TCP packets
		}

		if tcp.DstPort == port || tcp.SrcPort == port {
			// Determine direction: first packet to the port is client→server
			if tcp.DstPort == port {
				tcp.Direction = 0 // client→server
			} else {
				tcp.Direction = 1 // server→client
			}
			packets = append(packets, tcp)
		}
	}
	return packets, nil
}

// ExtractTLSRecords parses a reassembled TCP stream and extracts TLS records.
// The stream must be from a single direction (client→server or server→client).
func ExtractTLSRecords(stream []byte, direction int, baseTime time.Time, packetTimes []time.Time) []TLSRecord {
	var records []TLSRecord
	timeIdx := 0

	for len(stream) >= 5 {
		contentType := stream[0]
		version := binary.BigEndian.Uint16(stream[1:3])
		length := binary.BigEndian.Uint16(stream[3:5])

		// Sanity checks
		if length > 16384+256 { // Max TLS record is 16KB + some overhead
			break
		}
		if contentType < 20 || contentType > 23 {
			// Not a valid TLS record — skip byte and retry
			stream = stream[1:]
			continue
		}

		if int(length)+5 > len(stream) {
			break // Incomplete record
		}

		rec := TLSRecord{
			ContentType: contentType,
			Version:     version,
			Length:      length,
			Payload:     make([]byte, length),
			Direction:   direction,
		}
		copy(rec.Payload, stream[5:5+length])

		// Assign best-effort timestamp
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

// ParseHandshakeMessage parses a TLS handshake message from handshake record payload.
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

// Direction constants for FilterDirection.
const (
	DirBoth = iota
	DirClientToServer
	DirServerToClient
)

// FilteredStream holds reassembled TCP streams separated by direction.
type FilteredStream struct {
	ClientToServer []byte
	ServerToClient []byte

	// Timestamps at which data arrived (for timing analysis)
	ClientTimestamps []time.Time
	ServerTimestamps []time.Time

	// ServerPort is the port the server listens on
	ServerPort uint16
}

// ReassembleStreams opens a pcap, filters TCP packets for a port, and reassembles
// streams in each direction. This is a simplified reassembly that assumes:
//   - Packets arrive in order (valid for captured pcap files)
//   - Single TCP connection (first seen 5-tuple wins)
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

		// Filter by port
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

		// Check if this packet belongs to our connection
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

// NSSKeyLog represents a parsed NSS SSLKEYLOGFILE entry.
type NSSKeyLog struct {
	Label      string
	ClientRandom []byte
	Secret     []byte
}

// ParseNSSKeyLog parses an NSS-style SSLKEYLOGFILE.
// Format: <Label> <ClientRandom_hex> <Secret_hex>
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

// hexDecode decodes a hex string to bytes.
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

// ExtractClientRandom extracts ClientRandom from reassembled ClientHello bytes.
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

// TLS overhead estimates for different versions and ciphers.
const (
	// TLS 1.2 GCM overhead: 8 byte explicit nonce + 16 byte tag.
	TLS12GCMOverhead = 24

	// TLS 1.3 overhead: 1 byte inner content type + 16 byte tag.
	// Plus the 5-byte outer record header.
	TLS13Overhead = 17
)

// EstimatePlaintextSize estimates plaintext size from TLS record size.
// This is heuristic — actual overhead depends on cipher suite.
func EstimatePlaintextSize(recordLength uint16, version uint16) int {
	if version == TLSVersion13 {
		return int(recordLength) - TLS13Overhead
	}
	return int(recordLength) - TLS12GCMOverhead
}
