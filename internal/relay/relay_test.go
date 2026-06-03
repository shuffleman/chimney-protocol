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

	pool := newTunnelConnPool(nil, dialSem, connSem)
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
	}, dialSem, connSem)
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
