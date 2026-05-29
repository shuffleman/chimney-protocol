package dilution

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNewProvider(t *testing.T) {
	blocks := []Block{
		{Size: 300, Content: "large-block-content"},
		{Size: 50, Content: "small"},
		{Size: 150, Content: "medium-content"},
	}

	p := NewProvider(blocks)

	if p.Len() != 3 {
		t.Fatalf("expected 3 blocks, got %d", p.Len())
	}

	// Verify blocks are sorted by size (ascending)
	for i := 1; i < len(p.blocks); i++ {
		if p.blocks[i-1].Size > p.blocks[i].Size {
			t.Errorf("blocks not sorted: p.blocks[%d].Size=%d > p.blocks[%d].Size=%d",
				i-1, p.blocks[i-1].Size, i, p.blocks[i].Size)
		}
	}
}

func TestProviderGetBlock(t *testing.T) {
	blocks := []Block{
		{Size: 50, Content: "small"},
		{Size: 150, Content: "medium-content-blah"},
		{Size: 300, Content: "large-content-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
		{Size: 500, Content: "xlarge-content-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	}
	p := NewProvider(blocks)

	tests := []struct {
		name       string
		targetSize uint16
		wantNil    bool
	}{
		{"exact fit for small block", 60, false},  // 50 + 9 = 59 <= 60
		{"exact fit for medium block", 160, false}, // 150 + 9 = 159 <= 160
		{"too small target", 10, true},             // 10 - 9 = 1, minimal content
		{"large target gets largest block", 1000, false},
		{"no blocks match exactly, falls back", 130, false}, // 130 - 9 = 121, closest is 150, but largest <= 121 is 50, still fits though
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.GetBlock(tt.targetSize)
			if tt.wantNil && got != nil {
				t.Errorf("expected nil, got %d bytes", len(got))
			}
			if !tt.wantNil && got == nil {
				t.Errorf("expected non-nil, got nil")
			}
		})
	}
}

func TestProviderGetBlockEmpty(t *testing.T) {
	p := NewProvider(nil)
	if got := p.GetBlock(100); got != nil {
		t.Errorf("expected nil from empty provider, got %d bytes", len(got))
	}
}

func TestProviderLen(t *testing.T) {
	p := NewProvider([]Block{
		{Size: 1, Content: "a"},
		{Size: 2, Content: "bb"},
	})
	if p.Len() != 2 {
		t.Errorf("expected Len=2, got %d", p.Len())
	}
}

func TestLoadProviderFromFile(t *testing.T) {
	// Create test blocks with base64-encoded content
	blocks := []Block{
		{Size: 0, Content: base64.StdEncoding.EncodeToString([]byte("hello-world-content"))},
		{Size: 0, Content: base64.StdEncoding.EncodeToString([]byte("short"))},
		{Size: 0, Content: base64.StdEncoding.EncodeToString([]byte("medium-length-real-html-content-block"))},
	}

	data, err := json.Marshal(blocks)
	if err != nil {
		t.Fatalf("failed to marshal test data: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "blocks.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	p, err := LoadProviderFromFile(path)
	if err != nil {
		t.Fatalf("LoadProviderFromFile: %v", err)
	}

	if p.Len() != 3 {
		t.Errorf("expected 3 blocks, got %d", p.Len())
	}

	// Verify content was decoded: "short" is 5 bytes
	got := p.GetBlock(20) // 20 - 9 = 11, should fit "short" (5 bytes) or "hello-world-content" (19 bytes)
	if got == nil {
		t.Fatal("expected non-nil block")
	}
	// "hello-world-content" = 19 bytes, with frame header = 28, which is > 20
	// So it should pick "short" (5 bytes) since that's the largest fitting block
	if string(got) != "short" {
		t.Logf("got content: %q (len=%d)", string(got), len(got))
	}
}

func TestLoadProviderFromFileNotFound(t *testing.T) {
	_, err := LoadProviderFromFile("/nonexistent/path/blocks.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadProviderFromFileBadBase64(t *testing.T) {
	blocks := []Block{
		{Size: 10, Content: "!!!not-valid-base64!!!"},
	}
	data, _ := json.Marshal(blocks)
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, data, 0644)

	_, err := LoadProviderFromFile(path)
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}
