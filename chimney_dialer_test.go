package chimney

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/dilution"
	"github.com/shuffleman/chimney-protocol/internal/profile"
)

// TestDialContextHookUsed 验证设置 Config.DialContext 后,newTunnel 用它拨号
// 而非默认 net.DialTimeout(切网复用宿主 dialer 的基础)。
func TestDialContextHookUsed(t *testing.T) {
	called := false
	cfg := Config{
		RelayAddr:      "203.0.113.1:443",
		ConnectTimeout: time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			called = true
			if addr != "203.0.113.1:443" {
				t.Errorf("hook addr = %q", addr)
			}
			return nil, errors.New("hook-dial-sentinel")
		},
	}
	_, err := newTunnel(cfg, nil, nil)
	if !called {
		t.Fatal("Config.DialContext hook was not used")
	}
	if err == nil || !strings.Contains(err.Error(), "hook-dial-sentinel") {
		t.Fatalf("error should wrap the hook error, got %v", err)
	}
}

// TestReviveIfDeadTriggersRebuild 验证主动健康检查会重建已死隧道。
func TestReviveIfDeadTriggersRebuild(t *testing.T) {
	dead := make(chan struct{})
	close(dead)
	attempted := false
	d := &Dialer{
		pool: []*tunnel{{dead: dead}},
		dialNew: func(Config, *profile.Model, *dilution.Provider) (*tunnel, error) {
			attempted = true
			return nil, fmt.Errorf("rebuild attempted")
		},
	}
	d.reviveIfDead(0)
	if !attempted {
		t.Fatal("reviveIfDead did not attempt to rebuild a dead tunnel")
	}
}

// TestReviveIfDeadSkipsAlive 验证存活隧道不会被主动重建。
func TestReviveIfDeadSkipsAlive(t *testing.T) {
	attempted := false
	d := &Dialer{
		pool: []*tunnel{{dead: make(chan struct{})}}, // 未关闭 = 存活
		dialNew: func(Config, *profile.Model, *dilution.Provider) (*tunnel, error) {
			attempted = true
			return nil, fmt.Errorf("should not happen")
		},
	}
	d.reviveIfDead(0)
	if attempted {
		t.Fatal("alive tunnel must not be rebuilt by health check")
	}
}
