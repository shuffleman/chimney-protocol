// Package dilution provides real content blocks for the dilution stream.
//
// Dilution frames carry pre-recorded HTTP response content (HTML, CSS, JS, JSON)
// instead of random bytes. This makes the traffic semantically indistinguishable
// from real web browsing under DPI analysis. The content blocks are loaded from
// a JSON file that was captured from real HTTPS sessions to the whitelisted site.
package dilution

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// Block represents a single captured HTTP response chunk with its size.
type Block struct {
	Size    int    `json:"size"`
	Content string `json:"content"` // base64-encoded content
}

// Provider manages pre-recorded content blocks and selects appropriate
// blocks to match target record sizes.
type Provider struct {
	blocks []Block
}

// NewProvider creates a Provider from a slice of blocks.
func NewProvider(blocks []Block) *Provider {
	sort.Slice(blocks, func(i, j int) bool {
		return blocks[i].Size < blocks[j].Size
	})
	return &Provider{blocks: blocks}
}

// LoadProviderFromFile loads content blocks from a JSON file.
// The file format is a JSON array of Block objects with base64-encoded content.
func LoadProviderFromFile(path string) (*Provider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dilution: read file: %w", err)
	}

	var rawBlocks []Block
	if err := json.Unmarshal(data, &rawBlocks); err != nil {
		return nil, fmt.Errorf("dilution: parse blocks: %w", err)
	}

	// Decode base64 content and update sizes to reflect decoded length.
	for i := range rawBlocks {
		decoded, err := base64.StdEncoding.DecodeString(rawBlocks[i].Content)
		if err != nil {
			return nil, fmt.Errorf("dilution: decode block %d: %w", i, err)
		}
		rawBlocks[i].Content = string(decoded)
		rawBlocks[i].Size = len(decoded)
	}

	return NewProvider(rawBlocks), nil
}

// GetBlock returns a content block whose encoded size is close to targetSize.
// It returns the largest block that fits within targetSize (minus 9 bytes for
// the H2 frame header), looking at blocks up to 20% below targetSize if no
// exact fit is found.
func (p *Provider) GetBlock(targetSize uint16) []byte {
	if len(p.blocks) == 0 {
		return nil
	}

	// We need the block's frame (9-byte header + content) to fit in targetSize.
	// So max content size = targetSize - 9.
	maxContent := int(targetSize) - 9
	if maxContent <= 0 {
		return nil
	}

	// Find the largest block that fits within maxContent.
	// Treat blocks with size within 20% of maxContent as acceptable fits.
	minContent := int(float64(maxContent) * 0.8)

	// Try to find an exact-fit block: size <= maxContent but as large as possible.
	var best Block
	for _, b := range p.blocks {
		if b.Size <= maxContent && b.Size > best.Size {
			best = b
		}
	}

	// If the best fit is too small (less than 80% of maxContent), just use the
	// largest available block and let the caller pad the rest.
	if best.Size < minContent && len(p.blocks) > 0 {
		best = p.blocks[len(p.blocks)-1] // largest block available
		if best.Size > maxContent {
			// Truncation-proof: pick largest that fits
			best = Block{}
			for _, b := range p.blocks {
				if b.Size <= maxContent && b.Size > best.Size {
					best = b
				}
			}
		}
	}

	if best.Size == 0 {
		// No block fits at all
		return nil
	}

	return []byte(best.Content)
}

// Len returns the number of blocks in the provider.
func (p *Provider) Len() int {
	return len(p.blocks)
}
