package relay

import "testing"

// TestWantsTrafficProfile 验证下行塑形与上行 pacing 的 profile 需求已解耦:
// StealthMode 单开(EnableProfiling=false)仍需 profile(供下行记录采样),
// 这样关掉上行 pacing 提升上传时,下行记录伪装不退化。
func TestWantsTrafficProfile(t *testing.T) {
	cases := []struct {
		enableProfiling, stealth, want bool
	}{
		{false, false, false},
		{true, false, true}, // 仅上行 pacing
		{false, true, true}, // 仅下行塑形(关键:不依赖 EnableProfiling)
		{true, true, true},
	}
	for _, c := range cases {
		got := wantsTrafficProfile(&Config{EnableProfiling: c.enableProfiling, StealthMode: c.stealth})
		if got != c.want {
			t.Errorf("wantsTrafficProfile(profiling=%v,stealth=%v)=%v, want %v",
				c.enableProfiling, c.stealth, got, c.want)
		}
	}
}
