package chimney

import "testing"

func TestExpandFingerprintSpec(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want []string
	}{
		{"empty falls back to chrome", "", []string{"chrome"}},
		{"single", "firefox", []string{"firefox"}},
		{"comma list", "chrome,firefox,edge", []string{"chrome", "firefox", "edge"}},
		{"trims spaces", " chrome , firefox ", []string{"chrome", "firefox"}},
		{"drops empties", "chrome,,firefox,", []string{"chrome", "firefox"}},
		{"rotate keyword expands pool", "rotate", fingerprintRotatePool},
		{"auto keyword expands pool", "auto", fingerprintRotatePool},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandFingerprintSpec(tt.spec)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d (%v), want %d (%v)", len(got), got, len(tt.want), tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestValidateFingerprintSpec(t *testing.T) {
	valid := []string{"chrome", "chrome,firefox,edge", "rotate", "auto", "chrome-120,firefox-120"}
	for _, spec := range valid {
		if err := validateFingerprintSpec(spec); err != nil {
			t.Errorf("validateFingerprintSpec(%q) = %v, want nil", spec, err)
		}
	}

	invalid := []string{"nope", "chrome,bogus", "chrome , , notabrowser"}
	for _, spec := range invalid {
		if err := validateFingerprintSpec(spec); err == nil {
			t.Errorf("validateFingerprintSpec(%q) = nil, want error", spec)
		}
	}
}

func TestSelectFingerprint(t *testing.T) {
	// 单个名称始终返回该指纹。
	id, err := selectFingerprint("firefox")
	if err != nil {
		t.Fatalf("selectFingerprint(firefox): %v", err)
	}
	want, _ := parseFingerprint("firefox")
	if id != want {
		t.Errorf("single spec returned %v, want %v", id, want)
	}

	// 轮换列表:多次选取应覆盖到多个不同指纹(非恒定)。
	// ClientHelloID 含 func 字段不可比较,用 Client/Version 字符串去重。
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		got, err := selectFingerprint("chrome,firefox,edge")
		if err != nil {
			t.Fatalf("selectFingerprint(list): %v", err)
		}
		seen[got.Client+"/"+got.Version] = true
	}
	if len(seen) < 2 {
		t.Errorf("rotation produced %d distinct fingerprints over 200 draws, want >=2", len(seen))
	}

	// 非法规格应报错。
	if _, err := selectFingerprint("definitely-not-a-browser"); err == nil {
		t.Error("selectFingerprint(invalid) = nil error, want error")
	}
}
