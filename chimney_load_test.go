package chimney

import "testing"

func TestLeastBusyStart(t *testing.T) {
	d := &Dialer{pool: []*tunnel{{}, {}, {}, {}}}
	d.pool[0].recentBytes.Store(1000)
	d.pool[1].recentBytes.Store(50) // 最闲
	d.pool[2].recentBytes.Store(800)
	d.pool[3].recentBytes.Store(200)
	// next 会轮转,但负载最低的始终应被选中。
	for i := 0; i < 10; i++ {
		if got := d.leastBusyStart(4); got != 1 {
			t.Fatalf("leastBusyStart=%d, want 1 (least-loaded)", got)
		}
	}
}

func TestLeastBusyStartTiesRotate(t *testing.T) {
	// 全部并列(均 0)时应轮转打散,不总落到同一条。
	d := &Dialer{pool: []*tunnel{{}, {}, {}, {}}}
	seen := map[int]bool{}
	for i := 0; i < 20; i++ {
		seen[d.leastBusyStart(4)] = true
	}
	if len(seen) < 2 {
		t.Errorf("ties should spread across tunnels, only saw %v", seen)
	}
}

func TestDecayLoad(t *testing.T) {
	d := &Dialer{pool: []*tunnel{{}}}
	d.pool[0].recentBytes.Store(1000)
	d.decayLoad(0)
	if got := d.pool[0].recentBytes.Load(); got != 500 {
		t.Errorf("after decay recentBytes=%d, want 500", got)
	}
}
