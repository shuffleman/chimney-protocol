package h2engine

import "testing"

func TestPingFrame(t *testing.T) {
	op := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	// PING(非 ACK)
	f := PingFrame(op, false)
	fh, err := DecodeFrameHeader(f)
	if err != nil {
		t.Fatalf("DecodeFrameHeader: %v", err)
	}
	if fh.Type != FramePing {
		t.Errorf("type = 0x%x, want FramePing(0x6)", fh.Type)
	}
	if fh.Flags&FlagAck != 0 {
		t.Error("non-ack PING should not have ACK flag")
	}
	if fh.Length != 8 || fh.StreamID != 0 {
		t.Errorf("len=%d streamID=%d, want 8/0", fh.Length, fh.StreamID)
	}
	if string(f[FrameHeaderLen:]) != string(op[:]) {
		t.Error("opaque payload mismatch")
	}
	// PONG(ACK)
	pong := PingFrame(op, true)
	ph, _ := DecodeFrameHeader(pong)
	if ph.Flags&FlagAck == 0 {
		t.Error("ack PING(PONG) must have ACK flag")
	}
}
