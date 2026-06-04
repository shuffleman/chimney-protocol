package relay

import (
	"context"
	"errors"
	"net"
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
