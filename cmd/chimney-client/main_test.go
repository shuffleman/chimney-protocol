package main

import (
	"net"
	"testing"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/h2engine"
)

func TestTunnelConnDeliverFrameWaitsForFullStreamChannel(t *testing.T) {
	ch := make(chan *streamFrame, 1)
	ch <- &streamFrame{
		fh:      &h2engine.FrameHeader{StreamID: 1, Type: h2engine.FrameData},
		payload: []byte{0x02, 'a'},
	}

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	tc := &tunnelConn{
		Conn:    left,
		streams: map[uint32]chan *streamFrame{1: ch},
		quit:    make(chan struct{}),
		dead:    make(chan struct{}),
	}

	done := make(chan bool, 1)
	go func() {
		done <- tc.deliverFrame(
			&h2engine.FrameHeader{StreamID: 1, Type: h2engine.FrameData},
			[]byte{0x02, 'b'},
		)
	}()

	select {
	case <-done:
		t.Fatal("deliverFrame returned while stream channel was still full")
	case <-time.After(20 * time.Millisecond):
	}

	<-ch

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("deliverFrame reported failure after channel space became available")
		}
	case <-time.After(time.Second):
		t.Fatal("deliverFrame did not complete after channel space became available")
	}

	got := <-ch
	if string(got.payload) != string([]byte{0x02, 'b'}) {
		t.Fatalf("unexpected delivered payload: %v", got.payload)
	}
}
