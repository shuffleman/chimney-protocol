package pcap

import (
	"bytes"
	"testing"
)

// makeRecord 构造一条 TLS 握手记录:header(5) + handshake_type(1) + body。
func makeRecord(handshakeType byte, bodyLen int) []byte {
	body := make([]byte, bodyLen)
	body[0] = handshakeType
	rec := make([]byte, 5+bodyLen)
	rec[0] = 0x16 // handshake
	rec[1] = 0x03
	rec[2] = 0x01
	rec[3] = byte(bodyLen >> 8)
	rec[4] = byte(bodyLen & 0xff)
	copy(rec[5:], body)
	return rec
}

func TestExtractClientHelloRecord_OK(t *testing.T) {
	rec := makeRecord(0x01, 300) // ClientHello, 300-byte body
	// 流中再追加一条无关记录,确保只取出第一条且长度精确。
	stream := append(append([]byte{}, rec...), makeRecord(0x16, 50)...)

	got, err := ExtractClientHelloRecord(stream)
	if err != nil {
		t.Fatalf("ExtractClientHelloRecord: %v", err)
	}
	if len(got) != len(rec) {
		t.Errorf("len = %d, want %d (must not include trailing record)", len(got), len(rec))
	}
	if !bytes.Equal(got, rec) {
		t.Error("returned bytes do not match the first record")
	}
}

func TestExtractClientHelloRecord_Errors(t *testing.T) {
	tests := []struct {
		name   string
		stream []byte
	}{
		{"too short", []byte{0x16, 0x03}},
		{"not handshake", append([]byte{0x17, 0x03, 0x01, 0x00, 0x05}, make([]byte, 5)...)},
		{"not clienthello", makeRecord(0x02, 100)}, // ServerHello
		{"truncated body", []byte{0x16, 0x03, 0x01, 0x01, 0x00, 0x01, 0x02}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ExtractClientHelloRecord(tt.stream); err == nil {
				t.Errorf("expected error for %q, got nil", tt.name)
			}
		})
	}
}
