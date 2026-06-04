package relay

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestPendingStreamCancelUnblocksCreateWaitingForConnSlot(t *testing.T) {
	dialSem := make(chan struct{}, 1)
	connSem := make(chan struct{}, 1)
	connSem <- struct{}{}

	pool := newTunnelConnPool(nil, dialSem, connSem, nil)
	pool.addPending(1)

	errCh := make(chan error, 1)
	go func() {
		_, err := pool.createForStream(1, "127.0.0.1:1")
		errCh <- err
	}()

	select {
	case err := <-errCh:
		t.Fatalf("createForStream returned before cancellation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	pool.closeStream(1)

	select {
	case err := <-errCh:
		if !errors.Is(err, errStreamCanceled) {
			t.Fatalf("expected errStreamCanceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("createForStream did not unblock after pending stream cancellation")
	}
}

func TestPendingStreamCancelCancelsBackendDialer(t *testing.T) {
	dialSem := make(chan struct{}, 1)
	connSem := make(chan struct{}, 1)
	entered := make(chan struct{})

	pool := newTunnelConnPool(func(ctx context.Context, network, addr string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}, dialSem, connSem, nil)
	pool.addPending(1)

	errCh := make(chan error, 1)
	go func() {
		_, err := pool.createForStream(1, "example.com:443")
		errCh <- err
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("backend dialer was not invoked")
	}

	pool.closeStream(1)

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("backend dialer was not canceled")
	}
}

func TestConnectACLDenyPrivateRejectsLoopback(t *testing.T) {
	acl, err := newConnectACL(nil, nil, true)
	if err != nil {
		t.Fatalf("newConnectACL failed: %v", err)
	}

	if _, err := acl.resolveDialAddr(context.Background(), "127.0.0.1:80"); err == nil {
		t.Fatal("expected loopback CONNECT target to be rejected")
	}
}

func TestConnectACLAllowCIDRControlsDialTarget(t *testing.T) {
	acl, err := newConnectACL([]string{"198.51.100.0/24"}, nil, false)
	if err != nil {
		t.Fatalf("newConnectACL failed: %v", err)
	}

	addr, err := acl.resolveDialAddr(context.Background(), "198.51.100.10:443")
	if err != nil {
		t.Fatalf("expected allowed CONNECT target: %v", err)
	}
	if addr != "198.51.100.10:443" {
		t.Fatalf("unexpected dial address %q", addr)
	}

	if _, err := acl.resolveDialAddr(context.Background(), "203.0.113.10:443"); err == nil {
		t.Fatal("expected target outside allow CIDR to be rejected")
	}
}

func TestCloseStreamReleasesPoolResources(t *testing.T) {
	dialSem := make(chan struct{}, 1)
	connSem := make(chan struct{}, 1)
	pool := newTunnelConnPool(nil, dialSem, connSem, nil)

	clientConn, backendConn := net.Pipe()
	defer clientConn.Close()

	pool.addPending(1)
	writeCh := pool.registerWriteCh(1)
	pool.mu.Lock()
	pool.streams[1] = backendConn
	pool.mu.Unlock()

	pool.closeStream(1)

	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.streams) != 0 {
		t.Fatalf("streams not cleared: %d", len(pool.streams))
	}
	if len(pool.writeChs) != 0 {
		t.Fatalf("writeChs not cleared: %d", len(pool.writeChs))
	}
	if len(pool.pending) != 0 {
		t.Fatalf("pending not cleared: %d", len(pool.pending))
	}
	select {
	case _, ok := <-writeCh:
		if ok {
			t.Fatal("write channel is still open")
		}
	default:
		t.Fatal("write channel was not closed")
	}
}

func TestParseUDPAddrSupportsIPAndDomainTargets(t *testing.T) {
	tests := []struct {
		name     string
		frame    []byte
		wantPort int
		wantData []byte
	}{
		{
			name:     "IPv4",
			frame:    []byte{0x01, 192, 0, 2, 1, 0, 53, 'q'},
			wantPort: 53,
			wantData: []byte{'q'},
		},
		{
			name:     "IPv6",
			frame:    append(append([]byte{0x04}, net.ParseIP("2001:db8::1").To16()...), 3, 85, 'q'),
			wantPort: 853,
			wantData: []byte{'q'},
		},
		{
			name:     "Domain",
			frame:    append(append([]byte{0x03, byte(len("localhost"))}, []byte("localhost")...), 0, 53, 'q'),
			wantPort: 53,
			wantData: []byte{'q'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, data, err := parseUDPAddr(tt.frame)
			if err != nil {
				t.Fatalf("parseUDPAddr failed: %v", err)
			}
			if addr.Port != tt.wantPort {
				t.Fatalf("port = %d, want %d", addr.Port, tt.wantPort)
			}
			if addr.IP == nil {
				t.Fatal("resolved UDP address has nil IP")
			}
			if !reflect.DeepEqual(data, tt.wantData) {
				t.Fatalf("payload = %v, want %v", data, tt.wantData)
			}
		})
	}
}

func TestParseUDPAddrRejectsTruncatedDomainTarget(t *testing.T) {
	_, _, err := parseUDPAddr([]byte{0x03, 10, 'l', 'o'})
	if err == nil {
		t.Fatal("expected truncated domain UDP frame error")
	}
}

func TestParseUDPAddrRejectsEmptyDomainTarget(t *testing.T) {
	_, _, err := parseUDPAddr([]byte{0x03, 0, 0, 53, 'q'})
	if err == nil {
		t.Fatal("expected empty domain UDP frame error")
	}
}
